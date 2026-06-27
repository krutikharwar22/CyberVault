"""
security_core/middleware.py

ThreatDetectionMiddleware — runs on every request.

Pipeline:
  1. Extract features from URL, POST body, headers
  2. Check Redis counters for brute force / DoS patterns
  3. Run all 5 ML detectors in one pass
  4. On threat: log to DB, send to Wazuh, optionally block with 403
"""
import json
import logging
import time
from typing import Optional

from django.conf import settings
from django.http import JsonResponse
import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from security_core.threat_detector import ThreatDetector
from wazuh_integration.wazuh_agent import WazuhAgent
from security_core.feature_extraction import extract_request_features, extract_all_features

logger = logging.getLogger('security_core')

# Lazy singletons – created once per worker process
_detector: Optional[ThreatDetector] = None
_wazuh: Optional[WazuhAgent] = None

def _get_detector() -> ThreatDetector:
    global _detector
    if _detector is None:
        from pathlib import Path
        _detector = ThreatDetector(
            models_dir=Path(settings.BASE_DIR) / 'security_core' / 'ml_models' / 'trained'
        )
    return _detector


def _get_wazuh() -> WazuhAgent:
    global _wazuh
    if _wazuh is None:
        _wazuh = WazuhAgent(settings.WAZUH_CONFIG)
    return _wazuh


# ─── Redis counter helpers ────────────────────────────────────────────────────

def _redis_incr(key: str, ttl: int) -> int:
    """Increment a Redis counter with TTL. Returns new count."""
    try:
        import redis
        r = redis.Redis.from_url(settings.CELERY_BROKER_URL, decode_responses=True)
        pipe = r.pipeline()
        pipe.incr(key)
        pipe.expire(key, ttl)
        result = pipe.execute()
        return int(result[0])
    except Exception:
        return 0  # Redis unavailable → degrade gracefully


def _redis_get(key: str) -> int:
    try:
        import redis
        r = redis.Redis.from_url(settings.CELERY_BROKER_URL, decode_responses=True)
        val = r.get(key)
        return int(val) if val else 0
    except Exception:
        return 0


# ─── Middleware ───────────────────────────────────────────────────────────────

class ThreatDetectionMiddleware:
    """
    Plugs into Django's middleware chain.
    Runs before authentication so we can block at the edge.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.config = getattr(settings, 'DETECTION_CONFIG', {})
        self.whitelist = set(self.config.get('WHITELIST_IPS', ['127.0.0.1']))
        self.block = self.config.get('BLOCK_ON_DETECT', True)

    def __call__(self, request):
        start = time.monotonic()

        # Skip whitelisted IPs and static/media files
        ip = self._get_ip(request)
        if ip in self.whitelist or self._is_static(request.path):
            return self.get_response(request)

        detection_result = self._inspect(request, ip)

        if detection_result and detection_result.get('any_threat') and self.block:
            return self._block_response(request, detection_result)

        response = self.get_response(request)

        # Track failed auths in Redis for brute force detection
        if response.status_code in (401, 403):
            self._track_failed_auth(ip)

        elapsed = round((time.monotonic() - start) * 1000, 2)
        logger.debug(f"Middleware inspection completed in {elapsed}ms for {ip}")
        return response

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _inspect(self, request, ip: str) -> Optional[dict]:
        try:
            url = request.build_absolute_uri()
            message = ''
            post_data = ''
            query_string = request.META.get('QUERY_STRING', '')

            if request.method == 'POST':
                try:
                    body = request.body.decode('utf-8', errors='replace')
                    body_dict = json.loads(body) if body.startswith('{') else {}
                    message = body_dict.get('message', '') or body_dict.get('text', '')
                    post_data = body
                except Exception:
                    post_data = ''

            # Redis-based counters
            window = self.config.get('BRUTE_FORCE_WINDOW_SECONDS', 300)
            req_key = f'req_count:{ip}'
            fail_key = f'fail_count:{ip}'
            req_count = _redis_incr(req_key, window)
            fail_count = _redis_get(fail_key)
            time_window = float(window)

            req_meta = extract_request_features(
                ip=ip,
                path=request.path,
                method=request.method,
                headers=request.META,
                body_size=len(request.body) if hasattr(request, 'body') else 0,
                request_count=req_count,
                failed_auth_count=fail_count,
                time_window_seconds=time_window,
            )

            feature_map = extract_all_features(
                url=url,
                message=message,
                query_string=query_string,
                post_data=post_data,
                request_metadata=req_meta,
            )

            raw_data = {
                'url': url,
                'message': message,
                'query_string': query_string,
                'post_data': post_data,
                'rps': req_meta.get('rps', 0),
                'failed_auth_count': fail_count,
            }

            detector = _get_detector()
            results = detector.run_all(feature_map, raw_data)

            any_threat = any(v['is_threat'] for v in results.values())

            if any_threat:
                self._handle_threats(request, ip, results, url)

            return {**results, 'any_threat': any_threat}

        except Exception as e:
            logger.error(f"Threat inspection error: {e}", exc_info=True)
            return None

    def _handle_threats(self, request, ip: str, results: dict, url: str):
        """Log to DB and forward to Wazuh for all detected threats."""
        from threat_detection.models import ThreatLog
        from wazuh_integration.tasks import send_wazuh_alert_async

        for threat_type, result in results.items():
            if not result['is_threat']:
                continue

            # Async Celery task – non-blocking
            try:
                send_wazuh_alert_async.delay(
                    threat_type=threat_type,
                    confidence=result['confidence'],
                    severity=result['severity'],
                    source_ip=ip,
                    url=url,
                    method=request.method,
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                )
            except Exception as e:
                logger.warning(f"Celery task failed, sending alert synchronously: {e}")
                try:
                    wazuh = _get_wazuh()
                    wazuh.send_alert(
                        threat_type=threat_type,
                        confidence=result['confidence'],
                        severity=result['severity'],
                        source_ip=ip,
                        url=url,
                        method=request.method,
                    )
                except Exception as we:
                    logger.error(f"Wazuh alert failed: {we}")

            # Synchronous DB log (lightweight)
            try:
                ThreatLog.objects.create(
                    threat_type=threat_type,
                    confidence=result['confidence'],
                    severity=result['severity'],
                    source_ip=ip,
                    url=url[:2000],
                    method=request.method,
                    user_agent=request.META.get('HTTP_USER_AGENT', '')[:512],
                    path=request.path[:500],
                )
            except Exception as e:
                logger.error(f"ThreatLog DB write failed: {e}")

    def _track_failed_auth(self, ip: str):
        window = self.config.get('BRUTE_FORCE_WINDOW_SECONDS', 300)
        key = f'fail_count:{ip}'
        _redis_incr(key, window)

    @staticmethod
    def _get_ip(request) -> str:
        xff = request.META.get('HTTP_X_FORWARDED_FOR', '')
        return xff.split(',')[0].strip() if xff else request.META.get('REMOTE_ADDR', '0.0.0.0')

    @staticmethod
    def _is_static(path: str) -> bool:
        return path.startswith(('/static/', '/media/', '/favicon'))

    @staticmethod
    def _block_response(request, detection_result: dict) -> JsonResponse:
        threats = [k for k, v in detection_result.items() if isinstance(v, dict) and v.get('is_threat')]
        return JsonResponse(
            {
                'error': 'Request blocked by security policy',
                'code': 'THREAT_DETECTED',
                'threats': threats,
            },
            status=403,
        )