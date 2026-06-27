"""
security_core/feature_extraction.py

Feature extraction for threat detection models.
"""
from typing import Dict, Any


def extract_request_features(
    ip: str,
    path: str,
    method: str,
    headers: Dict[str, Any],
    body_size: int,
    request_count: int,
    failed_auth_count: int,
    time_window_seconds: float,
) -> Dict[str, Any]:
    """
    Extract features from HTTP request metadata.
    
    Returns:
        dict: Request features including RPS (requests per second) and auth metrics.
    """
    rps = request_count / time_window_seconds if time_window_seconds > 0 else 0.0
    
    return {
        'ip': ip,
        'path': path,
        'method': method,
        'body_size': body_size,
        'request_count': request_count,
        'failed_auth_count': failed_auth_count,
        'rps': rps,
        'time_window_seconds': time_window_seconds,
    }


def extract_all_features(
    url: str,
    message: str,
    query_string: str,
    post_data: str,
    request_metadata: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Extract all features for ML models.
    
    Args:
        url: Full request URL
        message: Message body or extracted text
        query_string: Query string parameters
        post_data: POST body data
        request_metadata: Request metadata from extract_request_features
        
    Returns:
        dict: Feature map for ML detectors.
    """
    return {
        'url': url,
        'message': message,
        'query_string': query_string,
        'post_data': post_data,
        **request_metadata,
    }
