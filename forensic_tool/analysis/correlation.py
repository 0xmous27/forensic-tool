"""
Correlation Engine for NTFS Timestamp Forgery Detection.

This module implements the core forensic logic for detecting timestamp
manipulation (timestomping) by cross-correlating timestamps from multiple
artifact sources.

Key detection strategies:
1. SI vs FN mismatch: STANDARD_INFORMATION timestamps differ from FILE_NAME
   timestamps — the most common indicator of timestomping.
2. USN journal inconsistency: File modification recorded in USN but SI
   timestamps show no change.
3. Impossible timestamps: Born time is after modified time.
4. Nanosecond precision zeroing: Timestomping tools often zero sub-second
   precision, leaving round timestamps.
5. Future timestamps: Timestamps set in the future relative to image acquisition.
6. Cluster of identical timestamps: Multiple files with identical timestamps
   suggest bulk manipulation.
7. Lack of corroboration: MFT claims a timestamp but no external source
   (USN, EVTX, LogFile, Registry) has activity near that time.
8. Multi-source contradiction: Multiple external sources agree on a DIFFERENT
   time period than what MFT claims — strong evidence of MFT tampering.
"""

import logging
from datetime import timedelta
from collections import defaultdict

from django.db.models import Q
from django.utils import timezone

from core.models import DiskImage, ForensicArtifact, ForgeryResult

logger = logging.getLogger(__name__)

# Tolerance window for timestamp comparison (2 seconds accounts for FAT/NTFS rounding)
TIMESTAMP_TOLERANCE = timedelta(seconds=2)

# Corroboration window: external source must have activity within ±24h of MFT claim
CORROBORATION_WINDOW = timedelta(hours=24)

# Threshold for sub-second precision check (timestamps with 0 microseconds are suspicious)
ZERO_SUBSECOND_THRESHOLD = 0

# External sources used for cross-source corroboration
EXTERNAL_SOURCES = ('USN', 'LOGFILE', 'EVTX', 'REGISTRY', 'VSS')


class CorrelationEngine:
    """
    Correlates timestamps across multiple forensic artifact sources
    and identifies anomalies indicative of timestamp forgery.
    """

    def __init__(self, disk_image: DiskImage):
        self.disk_image = disk_image
        self.anomalies_by_file = defaultdict(list)

    def run(self):
        """
        Execute all correlation checks and persist ForgeryResult records.
        Returns the number of files analyzed.
        """
        logger.info(f"Starting correlation analysis for: {self.disk_image.name}")

        # Delete previous results for this image
        ForgeryResult.objects.filter(disk_image=self.disk_image).delete()

        # Get all unique file paths that have MFT_SI artifacts
        file_paths = list(
            ForensicArtifact.objects
            .filter(disk_image=self.disk_image, source='MFT_SI')
            .values_list('file_path', flat=True)
            .distinct()
        )

        # Pre-load all artifacts grouped by file_path for performance
        self._preload_artifacts()

        total = len(file_paths)
        results = []
        for i, file_path in enumerate(file_paths):
            anomalies = self._analyze_file(file_path)
            if anomalies is not None:
                results.append(anomalies)

            # Update progress every 100 files
            if total > 0 and i % 100 == 0:
                pct = min(int(i / total * 100), 99)
                self.disk_image.analysis_progress = pct
                self.disk_image.analysis_label = f"Analyzing file {i}/{total}..."
                self.disk_image.save(update_fields=['analysis_progress', 'analysis_label'])

        # Bulk create results
        ForgeryResult.objects.bulk_create(results, batch_size=200)
        logger.info(f"Correlation complete. Analyzed {len(results)} files.")
        return len(results)

    def _preload_artifacts(self):
        """Pre-load all artifacts into memory grouped by file_path and source."""
        self._artifacts_cache = defaultdict(lambda: defaultdict(list))
        for art in ForensicArtifact.objects.filter(disk_image=self.disk_image).iterator():
            self._artifacts_cache[art.file_path][art.source].append(art)

    def _get_cached_artifacts(self, file_path, source=None):
        """Get artifacts from cache."""
        if source:
            return self._artifacts_cache[file_path].get(source, [])
        return self._artifacts_cache[file_path]

    def _analyze_file(self, file_path: str) -> ForgeryResult | None:
        """
        Run all anomaly checks for a single file path.
        Returns a ForgeryResult (not yet saved) or None if no SI artifact found.
        """
        artifacts_by_source = self._get_cached_artifacts(file_path)

        si_list = artifacts_by_source.get('MFT_SI', [])
        fn_list = artifacts_by_source.get('MFT_FN', [])
        usn_entries = artifacts_by_source.get('USN', [])
        logfile_entries = artifacts_by_source.get('LOGFILE', [])
        evtx_entries = artifacts_by_source.get('EVTX', [])
        registry_entries = artifacts_by_source.get('REGISTRY', [])
        vss_entries = artifacts_by_source.get('VSS', [])

        si = si_list[0] if si_list else None
        fn = fn_list[0] if fn_list else None

        if not si:
            return None

        file_name = si.file_name
        anomalies = []

        # --- Check 1: SI vs FN timestamp mismatch ---
        if fn:
            mismatch = self._check_si_fn_mismatch(si, fn)
            anomalies.extend(mismatch)

        # --- Check 2: Impossible timestamps (born > modified) ---
        impossible = self._check_impossible_timestamps(si)
        anomalies.extend(impossible)

        # --- Check 3: Zero sub-second precision (timestomping artifact) ---
        zero_precision = self._check_zero_subsecond(si)
        anomalies.extend(zero_precision)

        # --- Check 4: Future timestamps ---
        future = self._check_future_timestamps(si)
        anomalies.extend(future)

        # --- Check 5: USN journal vs SI mismatch ---
        if usn_entries:
            usn_mismatch = self._check_usn_mismatch(si, usn_entries)
            anomalies.extend(usn_mismatch)

        # --- Check 6 & 7: Cross-source corroboration ---
        external_artifacts = {
            'USN': usn_entries,
            'LOGFILE': logfile_entries,
            'EVTX': evtx_entries,
            'REGISTRY': registry_entries,
            'VSS': vss_entries,
        }
        corroboration = self._check_cross_source_corroboration(si, fn, external_artifacts)
        anomalies.extend(corroboration)

        return ForgeryResult(
            disk_image=self.disk_image,
            file_path=file_path,
            file_name=file_name,
            anomalies=anomalies,
            # Score is computed by the scoring engine; set 0 here
            forgery_score=0.0,
            classification='genuine',
        )

    def _check_si_fn_mismatch(self, si: ForensicArtifact, fn: ForensicArtifact) -> list:
        """
        Compare STANDARD_INFORMATION and FILE_NAME timestamps.

        Timestomping tools (e.g., Metasploit's timestomp, SetMACE) modify
        STANDARD_INFORMATION but cannot easily modify FILE_NAME without
        kernel-level access. A significant discrepancy is a strong forgery indicator.
        """
        anomalies = []
        pairs = [
            ('born', si.born_time, fn.born_time),
            ('modified', si.modified_time, fn.modified_time),
            ('accessed', si.accessed_time, fn.accessed_time),
            ('changed', si.changed_time, fn.changed_time),
        ]
        for ts_name, si_ts, fn_ts in pairs:
            if si_ts and fn_ts:
                diff = abs(si_ts - fn_ts)
                if diff > TIMESTAMP_TOLERANCE:
                    anomalies.append({
                        'type': 'SI_FN_MISMATCH',
                        'field': ts_name,
                        'si_value': si_ts.isoformat(),
                        'fn_value': fn_ts.isoformat(),
                        'diff_seconds': diff.total_seconds(),
                        'severity': 'high',
                        'description': (
                            f"SI {ts_name} ({si_ts}) differs from FN {ts_name} ({fn_ts}) "
                            f"by {diff.total_seconds():.1f}s — possible timestomping."
                        ),
                    })
        return anomalies

    def _check_impossible_timestamps(self, si: ForensicArtifact) -> list:
        """
        Detect logically impossible timestamp relationships.

        Cases:
        1. modified < born  → file modified before it existed (impossible)
        2. accessed < born  → file accessed before it existed (impossible)
        3. born > now       → file created in the future (impossible)

        The born=2026 / modified=2020 pattern is caught by case 1:
        modified(2020) < born(2026) → IMPOSSIBLE_TIMESTAMP (critical).
        """
        anomalies = []
        if si.born_time and si.modified_time:
            if si.modified_time < si.born_time - TIMESTAMP_TOLERANCE:
                diff = (si.born_time - si.modified_time).total_seconds()
                anomalies.append({
                    'type': 'IMPOSSIBLE_TIMESTAMP',
                    'description': (
                        f"Modified ({si.modified_time.date()}) is BEFORE born ({si.born_time.date()}) "
                        f"by {diff/86400:.0f} days. Logically impossible — strong forgery indicator."
                    ),
                    'severity': 'critical',
                    'diff_seconds': diff,
                })
        if si.born_time and si.accessed_time:
            if si.accessed_time < si.born_time - TIMESTAMP_TOLERANCE:
                diff = (si.born_time - si.accessed_time).total_seconds()
                anomalies.append({
                    'type': 'IMPOSSIBLE_TIMESTAMP',
                    'description': (
                        f"Accessed ({si.accessed_time.date()}) is BEFORE born ({si.born_time.date()}) "
                        f"by {diff/86400:.0f} days."
                    ),
                    'severity': 'high',
                    'diff_seconds': diff,
                })
        return anomalies

    def _check_zero_subsecond(self, si: ForensicArtifact) -> list:
        """
        Detect timestamps with zero microseconds across all four MACB fields.

        Many timestomping tools set timestamps to exact second boundaries
        (e.g., 2023-01-01 00:00:00.000000). When all four timestamps have
        zero microseconds, this is suspicious.
        """
        anomalies = []
        timestamps = [si.modified_time, si.accessed_time, si.changed_time, si.born_time]
        valid_ts = [t for t in timestamps if t is not None]

        if len(valid_ts) >= 3:
            zero_count = sum(1 for t in valid_ts if t.microsecond == 0)
            if zero_count == len(valid_ts):
                anomalies.append({
                    'type': 'ZERO_SUBSECOND_PRECISION',
                    'description': (
                        "All MACB timestamps have zero sub-second precision. "
                        "Timestomping tools often produce round timestamps."
                    ),
                    'severity': 'medium',
                })
        return anomalies

    def _check_future_timestamps(self, si: ForensicArtifact) -> list:
        """
        Detect timestamps set in the future relative to current time.
        Future timestamps are impossible for legitimate files.
        """
        anomalies = []
        now = timezone.now()
        for ts_name, ts in [('modified', si.modified_time), ('born', si.born_time),
                             ('accessed', si.accessed_time), ('changed', si.changed_time)]:
            if ts and ts > now + timedelta(days=1):
                anomalies.append({
                    'type': 'FUTURE_TIMESTAMP',
                    'field': ts_name,
                    'value': ts.isoformat(),
                    'severity': 'high',
                    'description': f"{ts_name} timestamp ({ts}) is set in the future.",
                })
        return anomalies

    def _check_usn_mismatch(self, si: ForensicArtifact, usn_entries: list) -> list:
        """
        Cross-reference SI timestamps with USN journal entries.

        If the USN journal records a file modification but the SI modified
        timestamp does not reflect this change, the SI timestamp may have
        been altered after the fact.
        """
        anomalies = []
        if not si.modified_time:
            return anomalies

        # Find USN entries for this file that are more recent than SI modified time
        for usn in usn_entries:
            if usn.modified_time and usn.modified_time > si.modified_time + TIMESTAMP_TOLERANCE:
                anomalies.append({
                    'type': 'USN_SI_MISMATCH',
                    'description': (
                        f"USN journal records activity at {usn.modified_time} "
                        f"but SI modified time is {si.modified_time}. "
                        "SI timestamp may have been backdated."
                    ),
                    'severity': 'high',
                    'usn_time': usn.modified_time.isoformat(),
                    'si_modified': si.modified_time.isoformat(),
                })
                break  # One finding is sufficient
        return anomalies

    def _check_cross_source_corroboration(self, si: ForensicArtifact,
                                           fn: ForensicArtifact | None,
                                           external_artifacts: dict) -> list:
        """
        Cross-source corroboration check.

        Verifies that the MFT-claimed timestamps are supported by at least one
        external artifact source. If external sources exist for this file but
        ALL point to a different time period, this is strong evidence of MFT tampering.

        This catches the case where an attacker modifies BOTH SI and FN attributes
        to look consistent, but forgets (or cannot modify) USN, EVTX, LogFile, etc.

        Two anomaly types:
        - LACK_OF_CORROBORATION: External artifacts exist but none confirm MFT time.
        - MULTI_SOURCE_CONTRADICTION: 2+ external sources agree on a DIFFERENT time.
        """
        anomalies = []

        # Get the MFT-claimed born/modified times (use SI as primary claim)
        mft_born = si.born_time
        mft_modified = si.modified_time

        if not mft_born and not mft_modified:
            return anomalies

        # Collect all timestamps from external sources
        external_timestamps = []  # list of (source_name, timestamp)
        for source_name, entries in external_artifacts.items():
            for entry in entries:
                # Collect all available timestamps from this entry
                for ts in (entry.modified_time, entry.born_time, entry.accessed_time, entry.changed_time):
                    if ts:
                        external_timestamps.append((source_name, ts))

        # If no external artifacts exist for this file, we can't corroborate — skip
        if not external_timestamps:
            return anomalies

        # Check corroboration: does ANY external timestamp fall within ±24h of MFT claim?
        corroborating_sources = set()
        contradicting_sources = {}  # source → earliest timestamp from that source

        for source_name, ext_ts in external_timestamps:
            corroborates = False
            if mft_born and abs(ext_ts - mft_born) <= CORROBORATION_WINDOW:
                corroborates = True
            if mft_modified and abs(ext_ts - mft_modified) <= CORROBORATION_WINDOW:
                corroborates = True

            if corroborates:
                corroborating_sources.add(source_name)
            else:
                # Track the earliest timestamp per contradicting source
                if source_name not in contradicting_sources or ext_ts < contradicting_sources[source_name]:
                    contradicting_sources[source_name] = ext_ts

        # Remove sources that both corroborate and contradict (they have multiple entries)
        for src in corroborating_sources:
            contradicting_sources.pop(src, None)

        num_external_sources = len(set(s for s, _ in external_timestamps))
        num_contradicting = len(contradicting_sources)

        # --- LACK_OF_CORROBORATION ---
        if not corroborating_sources and num_external_sources >= 1:
            anomalies.append({
                'type': 'LACK_OF_CORROBORATION',
                'description': (
                    f"MFT claims born={mft_born}, modified={mft_modified}, "
                    f"but {num_external_sources} external source(s) "
                    f"({', '.join(contradicting_sources.keys())}) have NO activity "
                    f"within ±24h of those times. MFT timestamps may be fabricated."
                ),
                'severity': 'medium' if num_contradicting < 2 else 'high',
                'external_sources_checked': num_external_sources,
                'corroborating_count': 0,
            })

        # --- MULTI_SOURCE_CONTRADICTION ---
        if num_contradicting >= 2:
            # Find the time period that external sources agree on
            contra_times = list(contradicting_sources.values())
            # Check if contradicting sources cluster together (within 48h of each other)
            contra_times.sort()
            cluster_window = timedelta(hours=48)
            clustered = all(
                abs(contra_times[i] - contra_times[0]) <= cluster_window
                for i in range(len(contra_times))
            )

            severity = 'critical' if num_contradicting >= 3 else 'high'

            contra_details = ', '.join(
                f"{src}: {ts.strftime('%Y-%m-%d %H:%M')}"
                for src, ts in contradicting_sources.items()
            )
            anomalies.append({
                'type': 'MULTI_SOURCE_CONTRADICTION',
                'description': (
                    f"{num_contradicting} external sources contradict MFT timestamps. "
                    f"MFT claims born={mft_born}, modified={mft_modified}. "
                    f"External sources show: [{contra_details}]. "
                    f"Sources {'cluster together' if clustered else 'span different times'} "
                    f"— {'strong' if clustered else 'moderate'} evidence of MFT tampering."
                ),
                'severity': severity,
                'contradicting_sources': num_contradicting,
                'clustered': clustered,
                'external_evidence': {src: ts.isoformat() for src, ts in contradicting_sources.items()},
            })

        return anomalies
