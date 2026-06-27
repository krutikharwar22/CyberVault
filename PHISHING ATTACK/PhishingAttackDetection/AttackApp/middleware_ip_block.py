"""Reject requests whose client IP is in BlockedIPAddress (staff-managed)."""

from django.http import HttpResponseForbidden

from .models import BlockedIPAddress


def client_ip_from_request(request) -> str:
    xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if xff:
        return xff.split(",")[0].strip() or "0.0.0.0"
    return request.META.get("REMOTE_ADDR", "0.0.0.0") or "0.0.0.0"


class BlockedIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path or ""
        if path.startswith(("/static/", "/media/")):
            return self.get_response(request)
        ip = client_ip_from_request(request)
        if BlockedIPAddress.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden(
                "This IP address has been blocked. If you believe this is an error, contact your administrator."
            )
        return self.get_response(request)
