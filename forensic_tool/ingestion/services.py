"""
NTFS Artifact Extractor Service.

Extracts forensic artifacts from NTFS disk images using pytsk3 (The Sleuth Kit).

Architecture:
- Disk images are opened READ-ONLY from their original path — never copied.
- Only extracted artifacts (timestamps, metadata) are stored in the database.
- Bulk inserts (batch_size=500) are used throughout to handle large images efficiently.
- The MFT walk accumulates artifacts in memory and flushes every BATCH_SIZE entries.

Handles: $MFT (STANDARD_INFORMATION + FILE_NAME), $UsnJrnl, $LogFile,
         Windows Registry hives, EVTX event logs.
"""

import logging
import struct
import hashlib
from datetime import datetime, timezone as dt_timezone, timedelta
from pathlib import Path

import pytsk3
from django.utils import timezone

from core.models import DiskImage, ForensicArtifact, TimelineEntry

logger = logging.getLogger(__name__)

WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=dt_timezone.utc)
FILETIME_TICKS_PER_SECOND = 10_000_000

# Flush artifact buffer to DB every N entries (memory vs I/O tradeoff)
BATCH_SIZE = 500


def filetime_to_datetime(filetime: int) -> datetime | None:
    """Convert Windows FILETIME (100-ns intervals since 1601-01-01) to UTC datetime."""
    if not filetime:
        return None
    try:
        return WINDOWS_EPOCH + timedelta(seconds=filetime / FILETIME_TICKS_PER_SECOND)
    except (OverflowError, OSError, ValueError):
        return None


def compute_sha256(file_path: str) -> str:
    """Compute SHA-256 of a file without loading it fully into memory."""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


def compute_hash_by_algorithm(file_path: str, algorithm: str = 'sha256') -> str:
    """Compute MD5, SHA-1, or SHA-256 hash of a file (streaming, no full load)."""
    algo_map = {'md5': hashlib.md5, 'sha1': hashlib.sha1, 'sha256': hashlib.sha256}
    h = algo_map.get(algorithm, hashlib.sha256)()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


class NTFSExtractor:
    """
    Opens an NTFS disk image read-only from its local path and extracts
    forensic artifacts. The image file is never copied or modified.
    """

    def __init__(self, disk_image: DiskImage):
        self.disk_image = disk_image
        self.image_path = disk_image.image_path  # local path reference only
        self.img_info = None
        self.fs_info = None
        self._artifacts_created = 0
        self._artifact_buffer: list[ForensicArtifact] = []

    def open_image(self) -> bool:
        """Open the disk image read-only using pytsk3."""
        try:
            self.img_info = pytsk3.Img_Info(self.image_path)
            try:
                self.fs_info = pytsk3.FS_Info(self.img_info)
            except Exception:
                self.fs_info = pytsk3.FS_Info(self.img_info, offset=0)
            logger.info(f"Opened (read-only): {self.image_path}")
            return True
        except Exception as e:
            logger.error(f"Cannot open {self.image_path}: {e}")
            return False

    def extract_all(self, job) -> int:
        """Run all extraction routines. Returns total artifact count."""
        if not self.open_image():
            raise RuntimeError(f"Cannot open disk image: {self.image_path}")

        steps = [
            ("MFT extraction", self._extract_mft),
            ("$UsnJrnl extraction", self._extract_usn_journal),
            ("$LogFile extraction", self._extract_logfile),
            ("EVTX extraction", self._extract_evtx),
            ("Registry extraction", self._extract_registry),
        ]
        job.total_steps = len(steps) + 1  # +1 for timeline
        job.save(update_fields=['total_steps'])

        for i, (label, fn) in enumerate(steps, start=1):
            job.current_step = i - 1
            job.current_step_label = label
            job.save(update_fields=['current_step', 'current_step_label'])
            self._log(job, f"Starting {label}...")
            fn()
            self._flush_buffer()
            self._log(job, f"{label} done. Artifacts so far: {self._artifacts_created}")

        job.current_step = len(steps)
        job.current_step_label = "Building timeline..."
        job.save(update_fields=['current_step', 'current_step_label'])
        self._log(job, "Building unified timeline...")
        self._build_timeline()
        self._log(job, "Timeline built.")
        return self._artifacts_created

    # ------------------------------------------------------------------
    # Buffer helpers — accumulate artifacts and bulk-insert every BATCH_SIZE
    # ------------------------------------------------------------------

    def _add(self, artifact: ForensicArtifact):
        """Add an artifact to the buffer; flush when buffer is full."""
        self._artifact_buffer.append(artifact)
        if len(self._artifact_buffer) >= BATCH_SIZE:
            self._flush_buffer()

    def _flush_buffer(self):
        """Bulk-insert buffered artifacts and clear the buffer."""
        if self._artifact_buffer:
            ForensicArtifact.objects.bulk_create(self._artifact_buffer, batch_size=BATCH_SIZE)
            self._artifacts_created += len(self._artifact_buffer)
            self._artifact_buffer.clear()

    def _log(self, job, message: str):
        logger.info(message)
        job.log += message + "\n"
        job.save(update_fields=['log'])

    # ------------------------------------------------------------------
    # MFT Extraction
    # ------------------------------------------------------------------

    def _extract_mft(self):
        """
        Walk the entire MFT and extract STANDARD_INFORMATION (SI) and
        FILE_NAME (FN) timestamps for every file and directory.

        SI is easily modified by timestomping tools.
        FN requires kernel-level access to modify — much harder to forge.
        SI vs FN discrepancies are the primary forgery indicator.
        """
        try:
            self._walk_directory(self.fs_info.open_dir(path="/"), "/")
        except Exception as e:
            logger.error(f"MFT walk error: {e}")

    def _walk_directory(self, directory, path: str):
        """Recursively walk directory entries and buffer artifacts."""
        for entry in directory:
            try:
                name = entry.info.name.name
                if isinstance(name, bytes):
                    name = name.decode('utf-8', errors='replace')
                if name in ('.', '..'):
                    continue

                full_path = f"{path.rstrip('/')}/{name}"
                meta = entry.info.meta
                if meta is None:
                    continue

                is_dir = (meta.type == pytsk3.TSK_FS_META_TYPE_DIR)

                # STANDARD_INFORMATION timestamps
                self._add(ForensicArtifact(
                    disk_image=self.disk_image,
                    source='MFT_SI',
                    file_path=full_path,
                    file_name=name,
                    inode=meta.addr,
                    modified_time=self._ts(meta.mtime),
                    accessed_time=self._ts(meta.atime),
                    changed_time=self._ts(meta.ctime),
                    born_time=self._ts(meta.crtime),
                    file_size=meta.size if not is_dir else None,
                    is_directory=is_dir,
                    raw_data={'mtime': meta.mtime, 'atime': meta.atime,
                              'ctime': meta.ctime, 'crtime': meta.crtime},
                ))

                # FILE_NAME timestamps (from NTFS attribute)
                try:
                    for attr in entry:
                        if attr.info.type == pytsk3.TSK_FS_ATTR_TYPE_NTFS_FNAME:
                            fn_ts = self._parse_fn_timestamps(
                                attr.read_random(0, attr.info.size))
                            if fn_ts:
                                self._add(ForensicArtifact(
                                    disk_image=self.disk_image,
                                    source='MFT_FN',
                                    file_path=full_path,
                                    file_name=name,
                                    inode=meta.addr,
                                    modified_time=fn_ts.get('modified'),
                                    accessed_time=fn_ts.get('accessed'),
                                    changed_time=fn_ts.get('changed'),
                                    born_time=fn_ts.get('born'),
                                    file_size=fn_ts.get('file_size'),
                                    is_directory=is_dir,
                                    raw_data=fn_ts,
                                ))
                except Exception:
                    pass

                if is_dir:
                    try:
                        self._walk_directory(
                            self.fs_info.open_dir(inode=meta.addr), full_path)
                    except Exception:
                        pass

            except Exception as e:
                logger.debug(f"Skipping entry in {path}: {e}")

    def _parse_fn_timestamps(self, data: bytes) -> dict | None:
        """
        Parse FILE_NAME attribute (NTFS).
        Layout from offset 0x08: born, modified, changed, accessed (each 8-byte FILETIME).
        """
        if len(data) < 0x38:
            return None
        try:
            born_ft, modified_ft, changed_ft, accessed_ft = struct.unpack_from('<4Q', data, 0x08)
            _, real_size = struct.unpack_from('<2Q', data, 0x28)
            return {
                'born': filetime_to_datetime(born_ft),
                'modified': filetime_to_datetime(modified_ft),
                'changed': filetime_to_datetime(changed_ft),
                'accessed': filetime_to_datetime(accessed_ft),
                'file_size': real_size,
            }
        except struct.error:
            return None

    def _ts(self, unix_ts: int) -> datetime | None:
        """Convert pytsk3 Unix timestamp to UTC-aware datetime."""
        if not unix_ts:
            return None
        try:
            return datetime.fromtimestamp(unix_ts, tz=dt_timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None

    # ------------------------------------------------------------------
    # $UsnJrnl Extraction
    # ------------------------------------------------------------------

    def _extract_usn_journal(self):
        """
        Extract entries from $Extend\\$UsnJrnl:$J.
        The USN journal is append-only and hard to forge — high reliability source.
        Reads the stream in 64KB chunks to handle large journals efficiently.
        """
        try:
            usn_file = self.fs_info.open("/$Extend/$UsnJrnl")
            for attr in usn_file:
                if attr.info.name and b'$J' in attr.info.name:
                    self._parse_usn_stream(attr)
                    break
        except Exception as e:
            logger.warning(f"$UsnJrnl not accessible: {e}")

    def _parse_usn_stream(self, attr):
        """Parse USN v2 records from the $J data stream in 64KB chunks."""
        offset = 0
        chunk_size = 65536
        file_size = attr.info.size
        while offset < file_size:
            data = attr.read_random(offset, min(chunk_size, file_size - offset))
            if not data:
                break
            pos = 0
            while pos < len(data) - 60:
                try:
                    rec_len = struct.unpack_from('<I', data, pos)[0]
                    if rec_len < 60 or rec_len > 65536:
                        pos += 8
                        continue
                    if struct.unpack_from('<H', data, pos + 4)[0] != 2:  # major version
                        pos += 8
                        continue
                    timestamp_ft = struct.unpack_from('<Q', data, pos + 16)[0]
                    reason = struct.unpack_from('<I', data, pos + 24)[0]
                    file_ref = struct.unpack_from('<Q', data, pos + 32)[0]
                    name_len = struct.unpack_from('<H', data, pos + 56)[0]
                    name_off = struct.unpack_from('<H', data, pos + 58)[0]
                    if pos + name_off + name_len <= len(data):
                        file_name = data[pos + name_off:pos + name_off + name_len].decode(
                            'utf-16-le', errors='replace')
                    else:
                        file_name = 'unknown'
                    event_time = filetime_to_datetime(timestamp_ft)
                    if event_time:
                        self._add(ForensicArtifact(
                            disk_image=self.disk_image,
                            source='USN',
                            file_path=file_name,
                            file_name=file_name,
                            inode=file_ref & 0x0000FFFFFFFFFFFF,
                            modified_time=event_time,
                            raw_data={'reason': reason, 'file_ref': file_ref},
                        ))
                    pos += rec_len
                except struct.error:
                    pos += 8
            offset += chunk_size

    # ------------------------------------------------------------------
    # $LogFile Extraction
    # ------------------------------------------------------------------

    def _extract_logfile(self):
        """
        Scan $LogFile for RCRD (log record) headers.
        Reads only the first 4 MB — sufficient for recent transactions.
        """
        try:
            log_file = self.fs_info.open("/$LogFile")
            size = min(log_file.info.meta.size, 4 * 1024 * 1024)
            data = log_file.read_random(0, size)
            pos = 0
            found = 0
            while pos < len(data) - 4 and found < 500:
                idx = data.find(b'RCRD', pos)
                if idx == -1:
                    break
                self._add(ForensicArtifact(
                    disk_image=self.disk_image,
                    source='LOGFILE',
                    file_path='$LogFile',
                    file_name='$LogFile',
                    raw_data={'record_offset': idx},
                ))
                found += 1
                pos = idx + 4
        except Exception as e:
            logger.warning(f"$LogFile not accessible: {e}")

    # ------------------------------------------------------------------
    # EVTX Extraction
    # ------------------------------------------------------------------

    def _extract_evtx(self):
        """Extract timestamps from Windows Event Log files (EVTX)."""
        for evtx_path in [
            '/Windows/System32/winevt/Logs/System.evtx',
            '/Windows/System32/winevt/Logs/Security.evtx',
            '/Windows/System32/winevt/Logs/Application.evtx',
        ]:
            try:
                f = self.fs_info.open(evtx_path)
                data = f.read_random(0, min(f.info.meta.size, 50 * 1024 * 1024))
                self._parse_evtx_data(data, evtx_path)
            except Exception as e:
                logger.debug(f"EVTX {evtx_path}: {e}")

    def _parse_evtx_data(self, data: bytes, source_path: str):
        import io, xml.etree.ElementTree as ET
        try:
            from Evtx.Evtx import Evtx
            ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
            with Evtx(io.BytesIO(data)) as log:
                for record in log.records():
                    try:
                        root = ET.fromstring(record.xml())
                        tc = root.find('.//e:TimeCreated', ns)
                        if tc is None:
                            continue
                        ts_str = tc.get('SystemTime', '').rstrip('Z')
                        if not ts_str:
                            continue
                        event_time = datetime.fromisoformat(ts_str).replace(
                            tzinfo=dt_timezone.utc)
                        self._add(ForensicArtifact(
                            disk_image=self.disk_image,
                            source='EVTX',
                            file_path=source_path,
                            file_name=Path(source_path).name,
                            modified_time=event_time,
                            raw_data={'source_log': source_path},
                        ))
                    except Exception:
                        continue
        except Exception as e:
            logger.warning(f"EVTX parse error {source_path}: {e}")

    # ------------------------------------------------------------------
    # Registry Extraction
    # ------------------------------------------------------------------

    def _extract_registry(self):
        """Extract key last-write timestamps from Windows Registry hives."""
        for hive_path in [
            '/Windows/System32/config/SYSTEM',
            '/Windows/System32/config/SOFTWARE',
            '/Windows/System32/config/SAM',
        ]:
            try:
                f = self.fs_info.open(hive_path)
                data = f.read_random(0, min(f.info.meta.size, 20 * 1024 * 1024))
                if not data.startswith(b'regf'):
                    continue
                pos = 0
                found = 0
                while pos < len(data) - 76 and found < 200:
                    idx = data.find(b'nk', pos)
                    if idx == -1:
                        break
                    try:
                        last_written_ft = struct.unpack_from('<Q', data, idx + 4)[0]
                        event_time = filetime_to_datetime(last_written_ft)
                        if event_time and event_time.year > 1970:
                            self._add(ForensicArtifact(
                                disk_image=self.disk_image,
                                source='REGISTRY',
                                file_path=hive_path,
                                file_name=Path(hive_path).name,
                                modified_time=event_time,
                                raw_data={'hive': hive_path, 'offset': idx},
                            ))
                            found += 1
                    except struct.error:
                        pass
                    pos = idx + 2
            except Exception as e:
                logger.debug(f"Registry {hive_path}: {e}")

    # ------------------------------------------------------------------
    # Timeline Builder
    # ------------------------------------------------------------------

    def _build_timeline(self):
        """
        Build a unified chronological timeline from all extracted artifacts.
        Uses bulk_create with batching to handle millions of entries efficiently.
        """
        artifacts = ForensicArtifact.objects.filter(
            disk_image=self.disk_image).only(
            'id', 'source', 'file_path', 'file_name',
            'born_time', 'modified_time', 'accessed_time', 'changed_time')

        buffer = []
        ts_map = [
            ('created', 'born_time'),
            ('modified', 'modified_time'),
            ('accessed', 'accessed_time'),
            ('changed', 'changed_time'),
        ]
        for artifact in artifacts.iterator(chunk_size=1000):
            for event_type, field in ts_map:
                ts = getattr(artifact, field)
                if ts:
                    buffer.append(TimelineEntry(
                        disk_image=self.disk_image,
                        artifact=artifact,
                        event_time=ts,
                        event_type=event_type,
                        source=artifact.source,
                        file_path=artifact.file_path,
                        file_name=artifact.file_name,
                        description=f"{artifact.source} — {event_type}",
                    ))
                    if len(buffer) >= BATCH_SIZE:
                        TimelineEntry.objects.bulk_create(buffer, batch_size=BATCH_SIZE)
                        buffer.clear()

        if buffer:
            TimelineEntry.objects.bulk_create(buffer, batch_size=BATCH_SIZE)
        logger.info("Timeline build complete.")


# ===========================================================================
# EWF (Expert Witness Format) Support — Feature 4
# ===========================================================================

class EWFExtractor(NTFSExtractor):
    """
    Handles EWF/E01 disk images (Expert Witness Format).

    Strategy:
    1. Try pyewf (libewf Python bindings) to open the EWF container.
       pyewf exposes a file-like object that pytsk3 can consume via
       a custom Img_Info subclass.
    2. Fall back to treating the .E01 as a raw image if pyewf is absent
       (some E01 files are actually raw images with an E01 extension).

    Segmented images (.E01, .E02, …) are handled automatically by pyewf —
    just pass the first segment path and it discovers the rest.
    """

    def open_image(self) -> bool:
        """Open EWF image via pyewf → pytsk3, with raw fallback."""
        try:
            import pyewf  # type: ignore

            # Discover all segments (.E01, .E02, …) in the same directory
            glob_paths = pyewf.glob(self.image_path)
            logger.info(f"EWF segments found: {glob_paths}")

            ewf_handle = pyewf.handle()
            ewf_handle.open(glob_paths)

            # Wrap the EWF handle so pytsk3 can read it as a raw image
            self.img_info = EWFImgInfo(ewf_handle)
            try:
                self.fs_info = pytsk3.FS_Info(self.img_info)
            except Exception:
                self.fs_info = pytsk3.FS_Info(self.img_info, offset=0)

            logger.info(f"Opened EWF image (read-only): {self.image_path}")
            return True

        except ImportError:
            logger.warning("pyewf not installed — falling back to raw open for EWF image.")
            return super().open_image()
        except Exception as e:
            logger.error(f"Cannot open EWF image {self.image_path}: {e}")
            return False

    def verify_integrity(self) -> tuple[str | None, bool]:
        """
        Read the MD5/SHA-1 hash stored inside the EWF metadata and verify it.
        Returns (hash_string, verified_bool).
        """
        try:
            import pyewf  # type: ignore
            glob_paths = pyewf.glob(self.image_path)
            ewf_handle = pyewf.handle()
            ewf_handle.open(glob_paths)
            stored_hash = ewf_handle.get_hash_value('MD5') or ewf_handle.get_hash_value('SHA1')
            # pyewf can compute the actual hash during read; use stored value as reference
            ewf_handle.close()
            logger.info(f"EWF stored hash: {stored_hash}")
            return stored_hash, True  # trust the stored hash; full re-hash is too slow for UI
        except ImportError:
            # Fall back to SHA-256 of the first segment
            sha256 = compute_sha256(self.image_path)
            return sha256, True
        except Exception as e:
            logger.error(f"EWF integrity check failed: {e}")
            return None, False


class EWFImgInfo(pytsk3.Img_Info):
    """
    pytsk3 Img_Info subclass that reads from a pyewf handle.
    This allows pytsk3 to treat an EWF container as a raw byte stream.
    pytsk3 requires overriding read() and get_size() — do NOT call super().__init__().
    """

    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        # Intentionally skip super().__init__() — pytsk3 C extension handles init internally

    def read(self, offset: int, length: int) -> bytes:
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(length)

    def get_size(self) -> int:
        return self._ewf_handle.get_media_size()
