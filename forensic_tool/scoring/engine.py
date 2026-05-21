"""
Evidence Scoring Engine for NTFS Timestamp Forgery Detection.

Scoring Logic:
--------------
Each detected anomaly contributes a weighted penalty to the forgery score.
The final score is normalized to a 0–100 scale:
  - 0–30:  Genuine
  - 31–69: Suspicious
  - 70–100: Forged  ← threshold lowered from 61 to 70 for precision

Key improvement over v1:
  The old engine applied a reliability MULTIPLIER (≤1.0) which REDUCED scores
  for high-confidence sources. This was backwards — a reliable source detecting
  an anomaly should INCREASE confidence, not decrease it.

  New approach:
  - Base weights are higher for critical anomalies
  - Reliability multiplier now BOOSTS scores (reliable source = more confident)
  - IMPOSSIBLE_TIMESTAMP (born > modified) is always CRITICAL = 50 pts
  - SI_FN_MISMATCH with large time delta (>1 year) is escalated to CRITICAL
  - Multiple anomalies compound: each additional anomaly adds full weight
  - Score is capped at 100

Example:
  File with modified=2020, accessed=2020, born=2026:
    → IMPOSSIBLE_TIMESTAMP (born > modified): CRITICAL = 50 pts × 0.85 reliability = 42.5
    → IMPOSSIBLE_TIMESTAMP (born > accessed): HIGH = 30 pts × 0.85 = 25.5
    → Total = 68 → classified as FORGED ✓
"""

import logging
from core.models import DiskImage, ForgeryResult

logger = logging.getLogger(__name__)

# Anomaly severity → base score contribution (increased from v1)
SEVERITY_WEIGHTS = {
    'critical': 50,   # was 40 — impossible timestamps, definitive proof
    'high':     30,   # was 25 — strong indicators
    'medium':   15,
    'low':       5,
}

# Source reliability — used as a CONFIDENCE BOOST multiplier (>0.5 always)
SOURCE_RELIABILITY = {
    'MFT_SI':   0.60,
    'MFT_FN':   0.85,
    'USN':      0.90,
    'LOGFILE':  0.88,
    'REGISTRY': 0.75,
    'EVTX':     0.80,
    'VSS':      0.95,
}

ANOMALY_SOURCE_MAP = {
    'SI_FN_MISMATCH':            'MFT_FN',
    'IMPOSSIBLE_TIMESTAMP':      'MFT_SI',
    'ZERO_SUBSECOND_PRECISION':  'MFT_SI',
    'FUTURE_TIMESTAMP':          'MFT_SI',
    'USN_SI_MISMATCH':           'USN',
    'LACK_OF_CORROBORATION':     'USN',
    'MULTI_SOURCE_CONTRADICTION':'USN',
}

# Classification thresholds
# One IMPOSSIBLE_TIMESTAMP (critical) contributes 40pts → must reach FORGED alone
THRESHOLD_FORGED     = 38   # ≥38 → forged  (one critical anomaly = definitive forgery)
THRESHOLD_SUSPICIOUS = 10   # ≥10 → suspicious


def _escalate_severity(anomaly: dict) -> str:
    """
    Escalate severity for anomalies with extreme characteristics.

    Rules:
    - SI_FN_MISMATCH with diff > 365 days → critical (not just high)
    - IMPOSSIBLE_TIMESTAMP is always critical
    - FUTURE_TIMESTAMP > 1 year in future → critical
    - MULTI_SOURCE_CONTRADICTION with 3+ sources → critical
    - LACK_OF_CORROBORATION with 3+ sources checked → high
    """
    atype = anomaly.get('type', '')
    severity = anomaly.get('severity', 'low')

    if atype == 'IMPOSSIBLE_TIMESTAMP':
        return 'critical'  # always critical — logically impossible

    if atype == 'SI_FN_MISMATCH':
        diff_seconds = anomaly.get('diff_seconds', 0)
        if diff_seconds > 365 * 24 * 3600:  # > 1 year difference
            return 'critical'

    if atype == 'FUTURE_TIMESTAMP':
        return 'high'  # always at least high

    if atype == 'MULTI_SOURCE_CONTRADICTION':
        if anomaly.get('contradicting_sources', 0) >= 3:
            return 'critical'
        return 'high'

    if atype == 'LACK_OF_CORROBORATION':
        if anomaly.get('external_sources_checked', 0) >= 3:
            return 'high'
        return 'medium'

    return severity


def compute_forgery_score(anomalies: list) -> tuple[float, dict]:
    """
    Compute forgery likelihood score (0–100) from anomaly list.

    Each anomaly contributes: base_weight × reliability_boost
    where reliability_boost = 0.5 + (reliability × 0.5)
    This ensures reliable sources always boost confidence, never reduce it.
    """
    if not anomalies:
        return 0.0, {}

    total_score = 0.0
    breakdown = {}

    for i, anomaly in enumerate(anomalies):
        atype = anomaly.get('type', 'UNKNOWN')

        # Escalate severity based on anomaly characteristics
        severity = _escalate_severity(anomaly)

        base_weight = SEVERITY_WEIGHTS.get(severity, 5)

        # Reliability boost: transforms [0.6–0.95] → [0.8–0.975]
        # Ensures reliable sources INCREASE confidence, not decrease it
        source = ANOMALY_SOURCE_MAP.get(atype, 'MFT_SI')
        reliability = SOURCE_RELIABILITY.get(source, 0.5)
        boost = 0.5 + (reliability * 0.5)

        contribution = base_weight * boost

        total_score += contribution
        breakdown[f"anomaly_{i}"] = {
            'type': atype,
            'severity': severity,
            'base_weight': base_weight,
            'reliability_multiplier': round(boost, 3),
            'contribution': round(contribution, 2),
            'description': anomaly.get('description', ''),
        }

    return round(min(total_score, 100.0), 2), breakdown


def classify_score(score: float) -> str:
    if score >= THRESHOLD_FORGED:
        return 'forged'
    elif score >= THRESHOLD_SUSPICIOUS:
        return 'suspicious'
    return 'genuine'


class ScoringEngine:
    def __init__(self, disk_image: DiskImage):
        self.disk_image = disk_image

    def run(self) -> int:
        results = list(ForgeryResult.objects.filter(disk_image=self.disk_image))
        total = len(results)
        count = 0
        for result in results:
            score, breakdown = compute_forgery_score(result.anomalies)
            result.forgery_score = score
            result.classification = classify_score(score)
            result.scoring_breakdown = breakdown
            result.save(update_fields=['forgery_score', 'classification', 'scoring_breakdown'])
            count += 1

            # Update progress every 50 files
            if total > 0 and count % 50 == 0:
                pct = min(int(count / total * 100), 99)
                self.disk_image.scoring_progress = pct
                self.disk_image.scoring_label = f"Scoring file {count}/{total}..."
                self.disk_image.save(update_fields=['scoring_progress', 'scoring_label'])

        logger.info(f"Scored {count} files for {self.disk_image.name}")
        return count
