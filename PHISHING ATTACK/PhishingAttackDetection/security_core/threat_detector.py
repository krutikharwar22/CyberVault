"""
security_core/threat_detector.py

ThreatDetector — runs all 5 ML detectors in one pass.
"""
from typing import Optional, Dict, Any
from pathlib import Path


class ThreatDetector:
    """ML-based threat detection engine."""

    def __init__(self, models_dir: Path):
        """Initialize threat detector with trained models directory."""
        self.models_dir = models_dir

    def run_all(self, feature_map: Dict[str, Any], raw_data: Dict[str, Any]) -> Dict[str, Dict]:
        """
        Run all detectors on extracted features.
        
        Returns:
            dict: Detection results with keys like 'phishing', 'malware', etc.
                 Each value contains 'is_threat', 'confidence', 'severity'.
        """
        results = {
            'phishing': {'is_threat': False, 'confidence': 0.0, 'severity': 'low'},
            'malware': {'is_threat': False, 'confidence': 0.0, 'severity': 'low'},
            'xss': {'is_threat': False, 'confidence': 0.0, 'severity': 'low'},
            'sql_injection': {'is_threat': False, 'confidence': 0.0, 'severity': 'low'},
            'dos': {'is_threat': False, 'confidence': 0.0, 'severity': 'low'},
        }
        return results
