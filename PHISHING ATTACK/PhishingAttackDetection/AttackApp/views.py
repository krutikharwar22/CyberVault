import json
import logging
import time
from datetime import datetime, timedelta
from typing import Optional



from django.contrib.admin.views.decorators import staff_member_required
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.validators import validate_email, validate_ipv46_address
from django.db.models import Count
from django.db.models import Max
from django.db.models.functions import TruncDay
from django.http import JsonResponse
from django.http import HttpResponse
from django.http import HttpResponseForbidden
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST
from django.core.mail import send_mail
from django.conf import settings
from .models import PasswordResetOTP
from .middleware_ip_block import client_ip_from_request
from .models import (
    ActiveUser,
    BlockedAttack,
    BlockedIPAddress,
    LoginLog,
    Log,
    RecentActivity,
    ScanResult,
    SystemHealth,
    ThreatDetected,
    ThreatLevel,
    UserNotificationState,
    UserSettings,
    WazuhSyncLog,
)
from .ml_predict import predict_url
from .file_url_extractor import extract_urls_from_upload
from .security_scanner import (
    scan_data_bundle,
    scan_email_bundle,
    scan_url_with_ips,
    summarize_for_storage,
    validate_and_normalize_scan_url,
    extract_urls,
)

logger = logging.getLogger(__name__)

def _log_action(action: str) -> None:
    try:
        Log.objects.create(action=action[:200])
    except Exception:
        logger.exception("Failed writing Log entry")


def _validate_client_ip(ip: str) -> str:
    ip = (ip or "").strip()
    if not ip:
        raise ValidationError("IP is required")
    validate_ipv46_address(ip)
    return ip

def forgot_password_view(request):
    """Step 1: User enters their username. OTP is sent from admin email."""
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        User = get_user_model()
        try:
            user = User.objects.get(username=username)
            if not user.email:
                messages.error(request, 'No email address is linked to this account. Contact the administrator.')
                return render(request, 'AttackApp/forgot_password.html')

            # Generate OTP and save it
            otp_obj = PasswordResetOTP.generate_for(user)

            # Send OTP email from admin email to user email
            send_mail(
                subject='CyberVault — Password Reset OTP',
                message=(
                    f'Hi {user.username},\n\n'
                    f'Your one-time password (OTP) is: {otp_obj.otp}\n\n'
                    f'This OTP is valid for 2 minutes only.\n'
                    f'If you did not request this, ignore this email.\n\n'
                    f'— CyberVault Admin'
                ),
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )

            # Store username in session to carry it to the next step
            request.session['otp_username'] = user.username
            messages.success(request, f'A 5-digit OTP has been sent to your registered email.')
            return redirect('AttackApp:verify_otp')

        except User.DoesNotExist:
            messages.error(request, 'No account found with that username.')

    return render(request, 'AttackApp/forgot_password.html')


def verify_otp_view(request):
    """Step 2: User enters the 5-digit OTP."""
    username = request.session.get('otp_username')
    if not username:
        messages.error(request, 'Session expired. Please start again.')
        return redirect('AttackApp:forgot_password')

    if request.method == 'POST':
        entered_otp = request.POST.get('otp', '').strip()
        User = get_user_model()
        try:
            user = User.objects.get(username=username)
            otp_obj = PasswordResetOTP.objects.filter(user=user, is_used=False).last()

            if otp_obj and otp_obj.is_valid() and otp_obj.otp == entered_otp:
                otp_obj.is_used = True
                otp_obj.save()
                # Allow access to reset password step
                request.session['otp_verified_user'] = username
                del request.session['otp_username']
                return redirect('AttackApp:reset_password')
            else:
                messages.error(request, 'Invalid or expired OTP. Please try again.')
        except User.DoesNotExist:
            messages.error(request, 'Something went wrong. Please start again.')
            return redirect('AttackApp:forgot_password')

    return render(request, 'AttackApp/verify_otp.html')


def reset_password_view(request):
    """Step 3: User sets a new password."""
    username = request.session.get('otp_verified_user')
    if not username:
        messages.error(request, 'Unauthorized access. Please start again.')
        return redirect('AttackApp:forgot_password')

    if request.method == 'POST':
        new_password = request.POST.get('new_password', '')
        confirm_password = request.POST.get('confirm_password', '')

        if len(new_password) < 8:
            messages.error(request, 'Password must be at least 8 characters.')
        elif new_password != confirm_password:
            messages.error(request, 'Passwords do not match.')
        else:
            User = get_user_model()
            user = User.objects.get(username=username)
            user.set_password(new_password)
            user.save()
            del request.session['otp_verified_user']
            messages.success(request, 'Password changed successfully. Please log in.')
            return redirect('AttackApp:login')

    return render(request, 'AttackApp/reset_password.html')


def _staff_apply_ip_block(request, ip: str, reason: str) -> None:
    reason = (reason or "").strip() or f"Manually blocked by {request.user.username}"
    BlockedIPAddress.objects.update_or_create(
        ip_address=ip,
        defaults={
            "reason": reason[:500],
            "blocked_by": request.user,
        },
    )
    RecentActivity.objects.create(
        activity_type="other",
        description=f"IP {ip} blocked by admin {request.user.username}",
        status="blocked",
        source_ip=ip,
        user=request.user.username,
        timestamp=timezone.now(),
    )
    _log_action(f"IP_BLOCK user={request.user.username} ip={ip}")


@staff_member_required
@require_POST
def block_ip(request):
    """Only staff may block IPs; entries are enforced by BlockedIPMiddleware."""
    try:
        body = json.loads(request.body or "{}")
        ip = body.get("ip")
        reason = (body.get("reason") or "").strip()
        ip = _validate_client_ip(str(ip))
        _staff_apply_ip_block(request, ip, reason)
        return JsonResponse({"success": True, "detail": f"{ip} is now blocked for all requests."})
    except ValidationError as ve:
        err = ve.messages[0] if getattr(ve, "messages", None) else str(ve)
        return JsonResponse({"success": False, "error": str(err)}, status=400)
    except json.JSONDecodeError:
        return JsonResponse({"success": False, "error": "invalid json"}, status=400)
    except Exception as exc:
        logger.error("block_ip error: %s", exc)
        return JsonResponse({"success": False, "error": str(exc)}, status=500)


@staff_member_required
@require_POST
def report_ip(request):
    """Staff-only audit trail when an IP is reported (review) but not necessarily blocked."""
    try:
        body = json.loads(request.body or "{}")
        ip = _validate_client_ip(str(body.get("ip") or ""))
        notes = (body.get("notes") or "").strip()[:500]
        RecentActivity.objects.create(
            activity_type="other",
            description=f'IP {ip} reported for review by {request.user.username}. Notes: {notes or "(none)"}',
            status="flagged",
            source_ip=ip,
            user=request.user.username,
            timestamp=timezone.now(),
        )
        _log_action(f"IP_REPORT user={request.user.username} ip={ip}")
        return JsonResponse({"success": True, "detail": "Report recorded."})
    except ValidationError as ve:
        err = ve.messages[0] if getattr(ve, "messages", None) else str(ve)
        return JsonResponse({"success": False, "error": str(err)}, status=400)
    except json.JSONDecodeError:
        return JsonResponse({"success": False, "error": "invalid json"}, status=400)
    except Exception as exc:
        logger.error("report_ip error: %s", exc)
        return JsonResponse({"success": False, "error": str(exc)}, status=500)


def _admin_incident_for_user(
    *,
    username: str,
    description: str,
    activity_type: str,
    status: str,
    source_ip: Optional[str] = None,
) -> None:
    """Record activity visible to staff in dashboard notifications (global feed for admins)."""
    try:
        RecentActivity.objects.create(
            activity_type=activity_type,
            description=description,
            status=status,
            source_ip=source_ip,
            user=username or None,
            timestamp=timezone.now(),
        )
    except Exception:
        logger.exception("Failed writing admin-facing RecentActivity")


def _resolve_dashboard_variant(user):
    """
    Return a dashboard variant based on role and recent user activity.
    """
    if getattr(user, "is_superuser", False) or getattr(user, "is_staff", False):
        return "admin", "System Admin", "Global security operations view"

    username = getattr(user, "username", "")
    recent_window = timezone.now() - timedelta(days=30)
    user_activity = RecentActivity.objects.filter(user=username, timestamp__gte=recent_window)

    scan_count = user_activity.filter(activity_type="scan").count()
    flagged_count = user_activity.filter(
        activity_type__in=["url_flag", "phishing", "brute_force"]
    ).count()

    if flagged_count >= 3:
        return "risk_watch", "Risk Watch", "Prioritized flagged and threat activity"
    if scan_count >= 5:
        return "scanner", "Active Scanner", "Focused on your recent scans and trends"
    return "starter", "New User", "Getting-started dashboard with key actions"


def _dashboard_queryset_for_user(user):
    """
    Scope dashboard datasets by user activity for non-admin users.
    """
    if getattr(user, "is_superuser", False) or getattr(user, "is_staff", False):
        return {
            "activities": RecentActivity.objects.all(),
            "logins": LoginLog.objects.all(),
            "scans": ScanResult.objects.order_by("-created_at"),
        }

    username = getattr(user, "username", "")
    return {
        "activities": RecentActivity.objects.filter(user=username),
        "logins": LoginLog.objects.filter(username=username),
        "scans": ScanResult.objects.filter(user=user).order_by("-created_at"),
    }


def _scan_queryset_for_user(user):
    if getattr(user, "is_superuser", False) or getattr(user, "is_staff", False):
        return ScanResult.objects.order_by("-created_at")
    return ScanResult.objects.filter(user=user).order_by("-created_at")


def _scan_dashboard_kpis(user):
    qs = _scan_queryset_for_user(user)
    today = timezone.now().date()
    total = qs.count()
    safe = qs.filter(result__iexact="safe").count()
    return {
        "scans_total": total,
        "scans_safe": safe,
        "scans_threats": total - safe,
        "scans_today": qs.filter(created_at__date=today).count(),
    }


def _scan_result_breakdown(user):
    """Threat-type distribution from the user's scan history (not system ThreatDetected)."""
    COLOR_MAP = {
        "phishing": "#ff4d6d",
        "malware": "#f9c74f",
        "phishing_domain": "#ff6b6b",
        "unverified_domain": "#ffa94d",
        "forwarded_phishing": "#e599f7",
        "phishing_heuristic": "#ff8787",
        "sql_injection": "#4cc9f0",
        "ddos": "#00b4d8",
        "safe": "#00ff88",
    }
    qs = _scan_queryset_for_user(user).exclude(result__iexact="safe")
    rows = list(
        qs.values("result")
        .annotate(count=Count("id"))
        .order_by("-count")[:8]
    )
    total = sum(r["count"] for r in rows) or 1
    breakdown = []
    for row in rows:
        label = (row["result"] or "unknown").replace("_", " ").title()
        breakdown.append({
            "result": row["result"],
            "label": label,
            "count": row["count"],
            "percentage": round(row["count"] / total * 100, 1),
            "color": COLOR_MAP.get(row["result"], "#00ffcc"),
        })
    return breakdown


def _serialize_scan_row(scan):
    domain_note = ""
    detail = getattr(scan, "detail", None) or {}
    if isinstance(detail, dict):
        ml = detail.get("ml") or {}
        dt = ml.get("domain_trust") or {}
        domain_note = dt.get("message") or ""
        if not domain_note and detail.get("message_domain_note"):
            domain_note = detail["message_domain_note"]
    kind = getattr(scan, "scan_kind", "url") or "url"
    return {
        "url": scan.url,
        "result": scan.result,
        "scan_kind": kind,
        "created_at": scan.created_at.isoformat(),
        "domain_note": domain_note[:160],
        "is_safe": (scan.result or "").lower() == "safe",
    }


def _notification_queryset_for_user(user):
    scoped = _dashboard_queryset_for_user(user)
    return scoped["activities"].filter(status__in=["blocked", "flagged", "detected"]).order_by("-timestamp")


def _notification_payload_for_user(user, limit=10):
    state, _ = UserNotificationState.objects.get_or_create(user=user)
    notifications_qs = _notification_queryset_for_user(user)
    unseen_qs = notifications_qs
    if state.last_seen_at:
        unseen_qs = notifications_qs.filter(timestamp__gt=state.last_seen_at)

    items = []
    for act in notifications_qs[:limit]:
        items.append(
            {
                "title": act.get_activity_type_display(),
                "description": act.description,
                "status": act.status,
                "time_ago": act.time_ago(),
                "timestamp": act.timestamp.isoformat(),
            }
        )
    return {"unread_count": unseen_qs.count(), "items": items}


# ---------------------------------------------------------------------------
# Auth views
# ---------------------------------------------------------------------------

def login_view(request):
    if request.user.is_authenticated:
        return redirect('AttackApp:dashboard')

    form = AuthenticationForm(request, data=request.POST or None)
    if request.method == 'POST':
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            # Track active users based on DB (used by dashboard).
            ip = client_ip_from_request(request)
            # Ensure a session key exists so we can distinguish parallel logins.
            if not request.session.session_key:
                request.session.save()
            ActiveUser.objects.update_or_create(
                username=user.username,
                session_key=request.session.session_key,
                defaults={
                    "ip_address": ip,
                    "is_active": True,
                },
            )
            # Log the login
            LoginLog.objects.create(
                username=user.username,
                ip_address=ip,
                status='safe',
            )
            _log_action(f"LOGIN success user={user.username} ip={ip}")
            messages.success(request, f'Welcome back, {user.username}.')
            next_url = (request.GET.get("next") or "").strip()
            return redirect(next_url or "AttackApp:dashboard")
        else:
            # Log failed login attempt.html
            username = request.POST.get('username', 'unknown')
            ip = client_ip_from_request(request)
            LoginLog.objects.create(
                username=username,
                ip_address=ip,
                status='blocked',
            )
            _log_action(f"LOGIN failed user={username} ip={ip}")
            _admin_incident_for_user(
                username=username,
                description=f'Failed login for "{username}" from {ip}',
                activity_type="brute_force",
                status="detected",
                source_ip=ip,
            )
    return render(request, 'AttackApp/login.html', {'form': form})


def register_view(request):
    if request.user.is_authenticated:
        return redirect('AttackApp:dashboard')

    form = UserCreationForm(request.POST or None)
    # Extend form with email/first/last name
    if request.method == 'POST':
        if form.is_valid():
            user = form.save(commit=False)
            user.email = request.POST.get('email', '')
            user.first_name = request.POST.get('first_name', '')
            user.last_name = request.POST.get('last_name', '')
            user.save()
            login(request, user)
            messages.success(request, f'Account created. Welcome, {user.username}.')
            return redirect('AttackApp:dashboard')
    return render(request, 'AttackApp/register.html', {'form': form})


def logout_view(request):
    if request.user.is_authenticated:
        # Mark user inactive
        ActiveUser.objects.filter(username=request.user.username, is_active=True).update(is_active=False)
    logout(request)
    messages.success(request, 'You have been logged out.')
    return redirect('AttackApp:login')  
def _recompute_threat_levels():
    COLOR_MAP = {
        'phishing':      '#ff4d6d',
        'malware':       '#f9c74f',
        'brute_force':   '#4cc9f0',
        'sql_injection': '#a8dadc',
        'ddos':          '#00b4d8',
        'other':         '#adb5bd',
    }
    type_counts = (
        ThreatDetected.objects
        .values('threat_type')
        .annotate(count=Count('id'))
        .order_by('-count')
    )
    total = sum(r['count'] for r in type_counts) or 1
    for row in type_counts:
        ttype = row['threat_type']
        pct = round(row['count'] / total * 100, 1)
        ThreatLevel.objects.update_or_create(
            threat_type=ttype,
            defaults={'percentage': pct, 'color': COLOR_MAP.get(ttype, '#00ffcc')},
        )


def _get_health():
    try:
        h = SystemHealth.objects.latest()
        return h.cpu_usage, h.memory_usage, h.disk_usage, h.health_percentage, h.status
    except SystemHealth.DoesNotExist:
        return 0.0, 0.0, 0.0, 0.0, "No data"


# ---------------------------------------------------------------------------
# Dashboard page
# ---------------------------------------------------------------------------

@login_required
def dashboard(request):
    _log_action(f"DASHBOARD_VIEW user={request.user.username}")

    scan_kpis = _scan_dashboard_kpis(request.user)
    scan_breakdown = _scan_result_breakdown(request.user)
    recent_scans = _scan_queryset_for_user(request.user)[:12]
    recent_scans_serialized = [_serialize_scan_row(s) for s in recent_scans]

    user_settings, _ = UserSettings.objects.get_or_create(user=request.user)
    dashboard_variant, dashboard_role_label, dashboard_subtitle = _resolve_dashboard_variant(request.user)
    notif_payload = _notification_payload_for_user(request.user, limit=8)
    is_admin = bool(request.user.is_staff or request.user.is_superuser)

    context = {
        "scan_kpis": scan_kpis,
        "scan_breakdown": scan_breakdown,
        "recent_scans": recent_scans,
        "recent_scans_data": recent_scans_serialized,
        "dashboard_refresh_ms": int(max(5, user_settings.dashboard_refresh_seconds) * 1000),
        "dashboard_variant": dashboard_variant,
        "dashboard_role_label": dashboard_role_label,
        "dashboard_subtitle": "Your URL, email, and file scan results",
        "is_admin_dashboard": is_admin,
        "notification_unread_count": notif_payload["unread_count"],
        "user": request.user,
    }
    return render(request, "AttackApp/dashboard.html", context)


@login_required
def profile_view(request):
    """Display user profile page."""
    user = request.user
    full_name = (user.get_full_name() or "").strip()
    initials = ((user.first_name[:1] if user.first_name else "") + (user.last_name[:1] if user.last_name else "")) or user.username[:2]

    if request.method == "POST":
        first_name = (request.POST.get("first_name") or "").strip()
        last_name = (request.POST.get("last_name") or "").strip()
        email = (request.POST.get("email") or "").strip()

        new_password = (request.POST.get("new_password") or "").strip()
        confirm_password = (request.POST.get("confirm_password") or "").strip()
        current_password = (request.POST.get("current_password") or "").strip()

        # Update profile fields
        user.first_name = first_name
        user.last_name = last_name
        if email:
            try:
                validate_email(email)
            except ValidationError:
                messages.error(request, "Invalid email address.")
                return redirect("AttackApp:profile")
            user.email = email
        else:
            user.email = ""

        # Optional password change
        if new_password or confirm_password:
            if not current_password:
                messages.error(request, "Current password is required to change your password.")
                return redirect("AttackApp:profile")
            if not user.check_password(current_password):
                messages.error(request, "Current password is incorrect.")
                return redirect("AttackApp:profile")
            if new_password != confirm_password:
                messages.error(request, "New password and confirmation do not match.")
                return redirect("AttackApp:profile")
            if len(new_password) < 8:
                messages.error(request, "New password must be at least 8 characters.")
                return redirect("AttackApp:profile")
            user.set_password(new_password)

        user.save()
        if new_password:
            update_session_auth_hash(request, user)  # keep user logged in
            messages.success(request, "Profile updated and password changed.")
        else:
            messages.success(request, "Profile updated.")
        return redirect("AttackApp:profile")

    context = {
        'page_title': 'Profile',
        'user': user,
        'profile_full_name': full_name or user.username,
        'profile_initials': initials.upper(),
        'profile_email': user.email or 'Not set',
        'profile_role': 'System Admin' if user.is_staff else 'User',
        'profile_joined': user.date_joined,
        'profile_last_login': user.last_login,
        'profile_is_staff': user.is_staff,
        'profile_is_superuser': user.is_superuser,
        'profile_is_active': user.is_active,
    }
    return render(request, 'AttackApp/profile.html', context)


@login_required
def scan_view(request):
    """Display scan page: URL (+ DNS IPs), pasted email (links + heuristics), or payload (SQLi / DoS patterns)."""
    result = None
    score = None
    score_display = None
    threat_type = None
    scanned_url = None
    email_body = ""
    payload_data = ""
    error = None
    scan_mode = "url"
    url_detail = None
    email_report = None
    data_report = None
    file_url_report = None

    if request.method == "POST":
        user_settings, _ = UserSettings.objects.get_or_create(user=request.user)
        scan_client_ip = client_ip_from_request(request)
        threshold = float(user_settings.url_threat_threshold)
        scan_mode = (request.POST.get("scan_mode") or "url").strip().lower()
        if scan_mode not in ("url", "email", "data"):
            scan_mode = "url"

        try:
            # Lightweight throttle (per-user, per-session) to avoid accidental abuse.
            # 12 scans / minute is plenty for interactive use.
            now_ts = int(time.time())
            window_s = 60
            limit = 12
            key = f"scan_ts_{request.user.id}"
            prev = request.session.get(key) or []
            prev = [int(x) for x in prev if isinstance(x, int) or (isinstance(x, str) and x.isdigit())]
            prev = [t for t in prev if now_ts - t <= window_s]
            if len(prev) >= limit:
                raise ValueError("Too many scans. Please wait a moment and try again.")
            prev.append(now_ts)
            request.session[key] = prev

            if scan_mode == "url":
                scanned_url = (request.POST.get("url") or "").strip()
                upload = request.FILES.get("url_file")

                if not scanned_url and not upload:
                    error = "Enter a URL to scan or upload a file containing URLs."
                elif upload and not scanned_url:
                    # Batch URL scan from uploaded file (defensive limits).
                    max_bytes = 5 * 1024 * 1024
                    max_urls = 25
                    raw = upload.read(max_bytes + 1)
                    if len(raw) > max_bytes:
                        raise ValueError("Upload too large. Please keep the file under 5MB.")

                    extracted = extract_urls_from_upload(
                        filename=getattr(upload, "name", "") or "",
                        content_type=getattr(upload, "content_type", "") or "",
                        raw=raw,
                        url_limit=max_urls + 15,
                    )
                    candidates = extracted["urls"]
                    urls = []
                    skipped = 0
                    for u in candidates:
                        try:
                            safe_u, _ = validate_and_normalize_scan_url(u)
                            urls.append(safe_u)
                        except Exception:
                            skipped += 1
                        if len(urls) >= max_urls:
                            break

                    out = []
                    threat_count = 0
                    for u in urls:
                        try:
                            bundle = scan_url_with_ips(u, predict_url=predict_url, threshold=threshold)
                            entry = {
                                "url": u,
                                "verdict": bundle.ml["verdict"],
                                "threat_type": bundle.ml["threat_type"],
                                "score": bundle.ml["score"],
                                "score_display": f"{float(bundle.ml['score']):.3f}" if user_settings.show_scan_scores else None,
                                "dns": bundle.dns,
                                "error": None,
                            }
                            out.append(entry)
                            store_result = (
                                bundle.ml["threat_type"]
                                if bundle.ml.get("threat_type") and bundle.ml["threat_type"] != "safe"
                                else "safe"
                            )
                            if bundle.ml["verdict"] == "threat" or store_result != "safe":
                                threat_count += 1
                            ScanResult.objects.create(
                                user=request.user,
                                url=u,
                                result=store_result,
                                scan_kind="url",
                                detail={"ml": bundle.ml, "dns": bundle.dns},
                            )
                        except Exception as exc:  # noqa: BLE001
                            out.append({"url": u, "error": str(exc)})

                    file_url_report = {
                        "count": len(out),
                        "threat_count": threat_count,
                        "skipped_count": skipped,
                        "notes": extracted.get("notes") or [],
                        "urls": out,
                    }
                    result = "threat" if threat_count else "safe"
                    threat_type = "file_batch" if threat_count else "safe"
                    _log_action(
                        f"URL_FILE_SCAN user={request.user.username} scanned={len(out)} threats={threat_count}"
                    )
                    if threat_count > 0 and user_settings.log_scan_to_recent_activity:
                        RecentActivity.objects.create(
                            activity_type="url_flag",
                            description=(
                                f"Batch URL scan ({len(out)} URLs): {threat_count} threat(s)"
                            ),
                            status="flagged",
                            user=request.user.username,
                            source_ip=scan_client_ip,
                            timestamp=timezone.now(),
                        )
                else:
                    # Single URL scan (existing behavior).
                    scanned_url, _ = validate_and_normalize_scan_url(scanned_url)
                    bundle = scan_url_with_ips(scanned_url, predict_url=predict_url, threshold=threshold)
                    pred_verdict = bundle.ml["verdict"]
                    threat_type = bundle.ml["threat_type"]
                    score = bundle.ml["score"]
                    result = pred_verdict
                    url_detail = {"ml": bundle.ml, "dns": bundle.dns}
                    if user_settings.show_scan_scores:
                        score_display = f"{score:.3f}"
                    store_result = threat_type if threat_type and threat_type != "safe" else "safe"
                    ScanResult.objects.create(
                        user=request.user,
                        url=scanned_url,
                        result=store_result,
                        scan_kind="url",
                        detail=url_detail,
                    )
                    _log_action(
                        f"URL_SCAN user={request.user.username} result={store_result} url={scanned_url}"
                    )
                    if user_settings.log_scan_to_recent_activity:
                        status = "flagged" if store_result != "safe" else "completed"
                        RecentActivity.objects.create(
                            activity_type="url_flag" if status == "flagged" else "scan",
                            description=(
                                f"URL scan: {scanned_url} → "
                                f"{(threat_type or result or 'unknown').upper()}"
                            ),
                            status=status,
                            user=request.user.username,
                            source_ip=scan_client_ip,
                            timestamp=timezone.now(),
                        )

            elif scan_mode == "email":
                email_body = request.POST.get("email_body") or ""
                if not email_body.strip():
                    error = "Paste email text (body or headers) to analyze."
                else:
                    email_report = scan_email_bundle(
                        email_body, predict_url=predict_url, threshold=threshold
                    )
                    threat_type = email_report["summary_threat"]
                    result = "threat" if threat_type != "safe" else "safe"
                    if email_report.get("message_domain_verdict") == "threat":
                        result = "threat"
                        threat_type = "phishing_domain"
                    elif email_report.get("message_domain_verdict") == "suspicious" and result == "safe":
                        result = "threat"
                        threat_type = "suspicious_forwarded"
                    if user_settings.show_scan_scores and email_report.get("urls"):
                        best = max(
                            (u.get("score") or 0.0) for u in email_report["urls"]
                        )
                        score_display = f"{best:.3f}" if email_report["urls"] else None
                    label = "email:" + email_body.strip().replace("\r", " ")[:200]
                    ScanResult.objects.create(
                        user=request.user,
                        url=label,
                        result=summarize_for_storage(email_report),
                        scan_kind="email",
                        detail=email_report,
                    )
                    _log_action(
                        f"EMAIL_SCAN user={request.user.username} result={summarize_for_storage(email_report)}"
                    )
                    if user_settings.log_scan_to_recent_activity:
                        st = summarize_for_storage(email_report)
                        status = "flagged" if st != "safe" else "completed"
                        RecentActivity.objects.create(
                            activity_type="url_flag" if status == "flagged" else "scan",
                            description=f"Email scan → {st.upper()}",
                            status=status,
                            user=request.user.username,
                            source_ip=scan_client_ip,
                            timestamp=timezone.now(),
                        )

            else:
                payload_data = request.POST.get("payload_data") or ""
                if not payload_data.strip():
                    error = "Paste log lines, query strings, or request body text to analyze."
                else:
                    data_report = scan_data_bundle(payload_data)
                    threat_type = data_report["summary_threat"]
                    result = "threat" if threat_type != "safe" else "safe"
                    label = "data:" + payload_data.strip().replace("\r", " ")[:200]
                    ScanResult.objects.create(
                        user=request.user,
                        url=label,
                        result=summarize_for_storage(data_report),
                        scan_kind="data",
                        detail=data_report,
                    )
                    _log_action(
                        f"DATA_SCAN user={request.user.username} result={summarize_for_storage(data_report)}"
                    )
                    if user_settings.log_scan_to_recent_activity:
                        st = summarize_for_storage(data_report)
                        status = "completed" if st == "safe" else "flagged"
                        RecentActivity.objects.create(
                            activity_type="other",
                            description=f"Payload scan → {st.upper()}",
                            status=status,
                            user=request.user.username,
                            source_ip=scan_client_ip,
                            timestamp=timezone.now(),
                        )

        except Exception as exc:
            logger.exception("Scan failed")
            error = str(exc)

    context = {
        "page_title": "New Scan",
        "scan_mode": scan_mode,
        "scan_url": scanned_url,
        "email_body": email_body,
        "payload_data": payload_data,
        "scan_result": result,
        "scan_threat_type": threat_type,
        "scan_score": score,
        "scan_score_display": score_display,
        "scan_error": error,
        "url_detail": url_detail,
        "file_url_report": file_url_report,
        "email_report": email_report,
        "data_report": data_report,
    }
    return render(request, "AttackApp/scan.html", context)


@login_required
@require_POST
def predict_url_api(request):
    """
    JSON API: POST {"url": "..."} -> {"verdict": "...", "threat_type": "...", "score": 0..1, "scores": {...}}
    """
    try:
        body = json.loads(request.body or "{}")
        url = (body.get("url") or "").strip()
        if not url:
            return JsonResponse({"error": "url is required"}, status=400)

        # Same URL validation as the UI scanner.
        url, _ = validate_and_normalize_scan_url(url)

        # Small throttle for the API as well (protects the server if this endpoint is called in a loop).
        now_ts = int(time.time())
        window_s = 60
        limit = 30
        key = f"predict_api_ts_{request.user.id}"
        prev = request.session.get(key) or []
        prev = [int(x) for x in prev if isinstance(x, int) or (isinstance(x, str) and x.isdigit())]
        prev = [t for t in prev if now_ts - t <= window_s]
        if len(prev) >= limit:
            return JsonResponse({"error": "rate limited"}, status=429)
        prev.append(now_ts)
        request.session[key] = prev

        user_settings, _ = UserSettings.objects.get_or_create(user=request.user)
        pred = predict_url(url, threshold=float(user_settings.url_threat_threshold))
        return JsonResponse(
            {
                "verdict": pred.verdict,
                "threat_type": pred.threat_type,
                "score": pred.score,
                "scores": pred.scores,
                "model": pred.model,
                "threshold": float(user_settings.url_threat_threshold),
            }
        )
    except json.JSONDecodeError:
        return JsonResponse({"error": "invalid json"}, status=400)
    except Exception as exc:
        logger.exception("predict_url_api failed")
        return JsonResponse({"error": str(exc)}, status=500)


@login_required
def history_view(request):
    """Display scan history page."""
    user_settings, _ = UserSettings.objects.get_or_create(user=request.user)
    _log_action(f"HISTORY_VIEW user={request.user.username}")
    scans = _scan_queryset_for_user(request.user)
    total_scans = scans.count()
    threat_scans = scans.exclude(result__iexact="safe").count()
    page_size = max(25, min(int(user_settings.history_page_size or 200), 1000))

    context = {
        'page_title': 'Scan History',
        'scan_history': scans[:page_size],
        'total_scans': total_scans,
        'threat_scans': threat_scans,
        'truncate_urls': bool(user_settings.truncate_urls_in_tables),
    }
    return render(request, 'AttackApp/history.html', context)


@login_required
def settings_view(request):
    """Display settings page."""
    user_settings, _ = UserSettings.objects.get_or_create(user=request.user)

    if request.method == "POST":
        action = (request.POST.get("action") or "save").strip().lower()

        if action == "clear_scan_history":
            deleted, _ = _scan_queryset_for_user(request.user).delete()
            _log_action(f"SCAN_HISTORY cleared by user={request.user.username} deleted={deleted}")
            messages.success(request, f"Cleared scan history ({deleted} rows removed).")
            return redirect("AttackApp:settings")

        try:
            dashboard_refresh_seconds = int(request.POST.get("dashboard_refresh_seconds") or user_settings.dashboard_refresh_seconds)
            dashboard_refresh_seconds = max(5, min(dashboard_refresh_seconds, 300))

            url_threat_threshold = float(request.POST.get("url_threat_threshold") or user_settings.url_threat_threshold)
            url_threat_threshold = max(0.05, min(url_threat_threshold, 0.95))

            show_scan_scores = (request.POST.get("show_scan_scores") == "on")
            enable_notifications = (request.POST.get("enable_notifications") == "on")
            history_page_size = int(request.POST.get("history_page_size") or user_settings.history_page_size)
            history_page_size = max(25, min(history_page_size, 1000))
            truncate_urls_in_tables = (request.POST.get("truncate_urls_in_tables") == "on")
            log_scan_to_recent_activity = (request.POST.get("log_scan_to_recent_activity") == "on")

            email_alerts_on_threat = (request.POST.get("email_alerts_on_threat") == "on")
            alert_email = (request.POST.get("alert_email") or "").strip()
            if alert_email:
                try:
                    validate_email(alert_email)
                except ValidationError:
                    messages.error(request, "Invalid alert email address.")
                    return redirect("AttackApp:settings")

            user_settings.dashboard_refresh_seconds = dashboard_refresh_seconds
            user_settings.url_threat_threshold = url_threat_threshold
            user_settings.show_scan_scores = show_scan_scores
            user_settings.enable_notifications = enable_notifications
            user_settings.history_page_size = history_page_size
            user_settings.truncate_urls_in_tables = truncate_urls_in_tables
            user_settings.log_scan_to_recent_activity = log_scan_to_recent_activity
            user_settings.email_alerts_on_threat = email_alerts_on_threat
            user_settings.alert_email = alert_email
            user_settings.save()

            _log_action(
                f"SETTINGS saved user={request.user.username} refresh={dashboard_refresh_seconds}s "
                f"threshold={url_threat_threshold} history={history_page_size}"
            )
            messages.success(request, "Settings saved.")
            return redirect("AttackApp:settings")
        except Exception as exc:
            logger.exception("Failed saving settings")
            messages.error(request, f"Failed to save settings: {exc}")

    context = {
        'page_title': 'Settings',
        'user_settings': user_settings,
    }
    _log_action(f"SETTINGS_VIEW user={request.user.username}")
    return render(request, 'AttackApp/settings.html', context)


@login_required
def export_scan_history_csv(request):
    user_settings, _ = UserSettings.objects.get_or_create(user=request.user)
    limit = max(100, min(int(user_settings.history_page_size or 200), 5000))
    qs = _scan_queryset_for_user(request.user)[:limit]

    import csv
    from io import StringIO

    buf = StringIO()
    w = csv.writer(buf)
    w.writerow(["created_at_utc", "scan_kind", "target", "result"])
    for s in qs:
        kind = getattr(s, "scan_kind", None) or "url"
        w.writerow([s.created_at.strftime("%Y-%m-%d %H:%M:%S"), kind, s.url, s.result])

    resp = HttpResponse(buf.getvalue(), content_type="text/csv; charset=utf-8")
    resp["Content-Disposition"] = 'attachment; filename="scan_history.csv"'
    _log_action(f"SCAN_HISTORY exported by user={request.user.username} rows={qs.count()}")
    return resp


@login_required
def logs_view(request):
    """Display logs page."""
    q = (request.GET.get("q") or "").strip()
    type_filter = (request.GET.get("type") or "all").strip().lower()
    since = (request.GET.get("since") or "").strip()  # expected: YYYY-MM-DD or YYYY-MM-DDTHH:MM

    qs = Log.objects.all()
    if q:
        qs = qs.filter(action__icontains=q)

    if type_filter and type_filter != "all":
        # Map UI filter -> action prefix written by _log_action
        prefix_map = {
            "scan": "URL_SCAN",
            "login": "LOGIN",
            "settings": "SETTINGS",
            "history": "SCAN_HISTORY",
            "ip": "IP_BLOCK",
        }
        p = prefix_map.get(type_filter)
        if p:
            qs = qs.filter(action__startswith=p)

    if since:
        try:
            from datetime import datetime

            dt = datetime.fromisoformat(since)
            if timezone.is_naive(dt):
                dt = timezone.make_aware(dt, timezone.get_current_timezone())
            qs = qs.filter(timestamp__gte=dt)
        except Exception:
            # Ignore bad since values; show results without the filter
            pass

    logs_total = Log.objects.count()
    if logs_total == 0:
        _log_action("SYSTEM Log initialized")
        logs_total = Log.objects.count()
    logs_filtered_total = qs.count()
    logs = qs.order_by("-timestamp")[:300]
    user_scans = _scan_queryset_for_user(request.user)
    scans_total = user_scans.count()
    scans_threats = user_scans.exclude(result__iexact="safe").count()
    context = {
        'page_title': 'Logs',
        'logs': logs,
        'logs_total': logs_total,
        'logs_filtered_total': logs_filtered_total,
        'scans_total': scans_total,
        'scans_threats': scans_threats,
        'filter_q': q,
        'filter_type': type_filter,
        'filter_since': since,
    }
    return render(request, 'AttackApp/logs.html', context)


# ---------------------------------------------------------------------------
# JSON API
# ---------------------------------------------------------------------------

@login_required
def dashboard_data(request):
    scan_kpis = _scan_dashboard_kpis(request.user)
    scan_breakdown = _scan_result_breakdown(request.user)
    recent_scans = [
        _serialize_scan_row(s)
        for s in _scan_queryset_for_user(request.user)[:12]
    ]
    notif_payload = _notification_payload_for_user(request.user, limit=8)
    return JsonResponse({
        "scan_kpis": scan_kpis,
        "scan_breakdown": scan_breakdown,
        "recent_scans": recent_scans,
        "notifications": {
            "unread_count": notif_payload["unread_count"],
        },
    })


@login_required
def notifications_api(request):
    return JsonResponse(_notification_payload_for_user(request.user, limit=12))


@login_required
@require_POST
def notifications_mark_read(request):
    state, _ = UserNotificationState.objects.get_or_create(user=request.user)
    state.last_seen_at = timezone.now()
    state.save(update_fields=["last_seen_at", "updated_at"])
    return JsonResponse({"success": True, "unread_count": 0})


@login_required
@require_POST
def delete_scan_result(request, scan_id: int):
    qs = ScanResult.objects.filter(id=scan_id)
    if not (request.user.is_staff or request.user.is_superuser):
        qs = qs.filter(user=request.user)
    if not qs.exists():
        return HttpResponseForbidden("Not allowed")
    qs.delete()
    messages.success(request, "History item deleted.")
    return redirect("AttackApp:history")


@login_required
@require_POST
def clear_my_history(request):
    qs = ScanResult.objects.filter(user=request.user)
    deleted, _ = qs.delete()
    _log_action(f"SCAN_HISTORY cleared_by_user user={request.user.username} deleted={deleted}")
    messages.success(request, "Your scan history was cleared.")
    return redirect("AttackApp:history")

# ---------------------------------------------------------------------------
# Quick actions
# ---------------------------------------------------------------------------

@login_required
@require_POST
def run_scan(request):
    try:
        # No dummy writes: this endpoint is a trigger hook only.
        # If you later integrate Wazuh polling / scanners, do the real work here.
        _log_action(f"SCAN_TRIGGER user={request.user.username}")
        return JsonResponse({'success': True, 'new_alerts': 0})
    except Exception as exc:
        logger.error("run_scan error: %s", exc)
        return JsonResponse({'success': False, 'error': str(exc)}, status=500)


@login_required
def view_report(request):
    seven_days_ago = timezone.now() - timedelta(days=7)
    scan_qs = _scan_queryset_for_user(request.user).filter(created_at__gte=seven_days_ago)
    daily = (
        scan_qs.exclude(result__iexact="safe")
        .annotate(day=TruncDay("created_at"))
        .values("day", "result")
        .annotate(count=Count("id"))
        .order_by("day")
    )
    report = {}
    for row in daily:
        if not row["day"]:
            continue
        day_str = row["day"].strftime("%Y-%m-%d")
        if day_str not in report:
            report[day_str] = {}
        report[day_str][row["result"]] = row["count"]

    return JsonResponse({'report': report})

# ---------------------------------------------------------------------------
# Admin-only: Users + login counts
# ---------------------------------------------------------------------------

@staff_member_required
def admin_users_view(request):
    """
    Staff-only user directory with login counts from LoginLog.
    """
    User = get_user_model()

    # Aggregate LoginLog by username (not FK), then join in Python.
    login_agg = {
        row["username"]: row
        for row in (
            LoginLog.objects.values("username")
            .annotate(login_count=Count("id"), last_login_time=Max("login_time"))
        )
    }

    users = []
    for u in User.objects.all().order_by("username"):
        key = getattr(u, "username", "") or ""
        a = login_agg.get(key, {})
        users.append(
            {
                "username": key,
                "full_name": (getattr(u, "get_full_name", lambda: "")() or "").strip(),
                "email": getattr(u, "email", "") or "",
                "is_staff": bool(getattr(u, "is_staff", False)),
                "is_superuser": bool(getattr(u, "is_superuser", False)),
                "is_active": bool(getattr(u, "is_active", True)),
                "date_joined": getattr(u, "date_joined", None),
                "last_login": getattr(u, "last_login", None),
                "login_count": int(a.get("login_count") or 0),
                "last_login_time": a.get("last_login_time"),
            }
        )

    users.sort(key=lambda r: (-r["login_count"], r["username"].lower()))

    context = {
        "page_title": "Admin Users",
        "users": users,
        "users_total": len(users),
        "logins_total": LoginLog.objects.count(),
    }
    return render(request, "AttackApp/admin_users.html", context)


@staff_member_required
@require_POST
def admin_user_toggle_active(request):
    """Enable or disable a user account (staff only)."""
    User = get_user_model()
    username = (request.POST.get("username") or "").strip()
    want_active = request.POST.get("active") == "1"
    if not username:
        messages.error(request, "Missing username.")
        return redirect("AttackApp:admin_users")
    target = User.objects.filter(username=username).first()
    if not target:
        messages.error(request, "User not found.")
        return redirect("AttackApp:admin_users")
    if target.pk == request.user.pk:
        messages.error(request, "You cannot enable or disable your own account from this screen.")
        return redirect("AttackApp:admin_users")
    if target.is_superuser and not request.user.is_superuser:
        messages.error(request, "Only a superuser may change another superuser account.")
        return redirect("AttackApp:admin_users")

    target.is_active = want_active
    target.save(update_fields=["is_active"])
    _log_action(
        f"ADMIN_USER_ACTIVE user={request.user.username} target={username} active={want_active}"
    )
    RecentActivity.objects.create(
        activity_type="login",
        description=f'Admin {request.user.username} set account "{username}" to '
        f'{"ACTIVE" if want_active else "DISABLED"}',
        status="successful" if want_active else "blocked",
        user=username,
        source_ip=client_ip_from_request(request),
        timestamp=timezone.now(),
    )
    messages.success(
        request,
        f'User "{username}" is now {"enabled" if want_active else "disabled"}.',
    )
    return redirect("AttackApp:admin_users")


@staff_member_required
def admin_security_view(request):
    """Staff: recent suspicious signals and blocked IPs (block / report / unblock)."""
    incidents = RecentActivity.objects.filter(
        status__in=["flagged", "detected", "blocked"]
    ).order_by("-timestamp")[:60]
    blocked = BlockedIPAddress.objects.order_by("-created_at")[:200]
    context = {
        "page_title": "Admin Security",
        "incidents": incidents,
        "blocked_ips": blocked,
    }
    return render(request, "AttackApp/admin_security.html", context)


@staff_member_required
@require_POST
def admin_block_ip_form(request):
    """HTML form POST from admin security page."""
    ip_raw = (request.POST.get("ip") or "").strip()
    reason = (request.POST.get("reason") or "").strip()
    try:
        ip = _validate_client_ip(ip_raw)
        _staff_apply_ip_block(request, ip, reason)
        messages.success(request, f"IP {ip} is now blocked.")
    except ValidationError:
        messages.error(request, "Invalid IP address.")
    return redirect("AttackApp:admin_security")


@staff_member_required
@require_POST
def admin_report_ip_form(request):
    ip_raw = (request.POST.get("ip") or "").strip()
    notes = (request.POST.get("notes") or "").strip()[:500]
    try:
        ip = _validate_client_ip(ip_raw)
    except ValidationError:
        messages.error(request, "Invalid IP address.")
        return redirect("AttackApp:admin_security")
    RecentActivity.objects.create(
        activity_type="other",
        description=f'IP {ip} reported for review by {request.user.username}. Notes: {notes or "(none)"}',
        status="flagged",
        source_ip=ip,
        user=request.user.username,
        timestamp=timezone.now(),
    )
    _log_action(f"IP_REPORT user={request.user.username} ip={ip}")
    messages.success(request, "Report recorded.")
    return redirect("AttackApp:admin_security")


@staff_member_required
@require_POST
def admin_unblock_ip(request):
    ip_raw = (request.POST.get("ip") or "").strip()
    try:
        ip = _validate_client_ip(ip_raw)
    except ValidationError:
        messages.error(request, "Invalid IP address.")
        return redirect("AttackApp:admin_security")
    deleted, _ = BlockedIPAddress.objects.filter(ip_address=ip).delete()
    if deleted:
        _log_action(f"IP_UNBLOCK user={request.user.username} ip={ip}")
        RecentActivity.objects.create(
            activity_type="other",
            description=f"IP {ip} unblocked by admin {request.user.username}",
            status="successful",
            source_ip=ip,
            user=request.user.username,
            timestamp=timezone.now(),
        )
        messages.success(request, f"IP {ip} is no longer blocked.")
    else:
        messages.info(request, "That IP was not on the block list.")
    return redirect("AttackApp:admin_security")