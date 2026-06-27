#!/usr/bin/env python3
"""
wazuh_integration/active_response/django_block_ip.py

Wazuh Active Response script.
Deploy to: /var/ossec/active-response/bin/django_block_ip.py
Make executable: chmod 750 /var/ossec/active-response/bin/django_block_ip.py
Owner: root:wazuh

This script is called by the Wazuh agent when rule 100010 fires.
It calls the Django API to add the IP to BlockedIP and optionally
adds an iptables rule.

Wazuh AR input (stdin JSON):
  {
    "version": 1,
    "origin": {...},
    "command": "add" | "delete",
    "parameters": {
      "alert": { "data": { "source_ip": "1.2.3.4", "threat_type": "..." } },
      "program": "django_block_ip"
    }
  }
"""
import sys
import json
import subprocess
import logging
import os
import urllib.request
import urllib.parse

LOG_FILE = '/var/ossec/logs/active-responses.log'
DJANGO_API = os.environ.get('DJANGO_API_URL', 'http://localhost:8000')
DJANGO_TOKEN = os.environ.get('DJANGO_AR_TOKEN', '')

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s django_block_ip %(levelname)s: %(message)s',
)
logger = logging.getLogger('django_block_ip')


def block_ip_iptables(ip: str, action: str = 'add'):
    """Add or remove iptables DROP rule."""
    flag = '-I' if action == 'add' else '-D'
    cmd = ['iptables', flag, 'INPUT', '-s', ip, '-j', 'DROP']
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        logger.info(f"iptables {action}: {ip}")
    except subprocess.CalledProcessError as e:
        logger.error(f"iptables failed for {ip}: {e.stderr.decode()}")


def notify_django(ip: str, reason: str, threat_type: str, action: str = 'add'):
    """Call Django REST API to update BlockedIP model."""
    if not DJANGO_TOKEN:
        logger.warning("DJANGO_AR_TOKEN not set – skipping Django API notification")
        return

    try:
        payload = json.dumps({
            'ip_address': ip,
            'reason': reason,
            'threat_type': threat_type,
            'action': action,
            'blocked_by': 'wazuh_ar',
        }).encode('utf-8')

        req = urllib.request.Request(
            f'{DJANGO_API}/api/threats/block-ip/',
            data=payload,
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {DJANGO_TOKEN}',
            },
            method='POST' if action == 'add' else 'DELETE',
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            logger.info(f"Django API response: {resp.status} for {ip}")
    except Exception as e:
        logger.error(f"Django API call failed: {e}")


def main():
    try:
        raw = sys.stdin.read()
        data = json.loads(raw)
    except Exception as e:
        logger.error(f"Failed to parse AR input: {e}")
        sys.exit(1)

    command = data.get('command', 'add')
    alert = data.get('parameters', {}).get('alert', {})
    alert_data = alert.get('data', {})

    source_ip = alert_data.get('source_ip', '')
    threat_type = alert_data.get('threat_type', 'unknown')
    severity = alert_data.get('severity', 'high')

    if not source_ip:
        logger.error("No source_ip in alert data")
        sys.exit(1)

    # Skip private/loopback IPs
    if source_ip.startswith(('127.', '10.', '192.168.', '172.')):
        logger.info(f"Skipping private IP: {source_ip}")
        sys.exit(0)

    reason = f"Wazuh AR: {threat_type} ({severity}) detected"
    logger.info(f"Active response: {command} block for {source_ip} ({threat_type})")

    block_ip_iptables(source_ip, action=command)
    notify_django(source_ip, reason, threat_type, action=command)

    sys.exit(0)


if __name__ == '__main__':
    main()