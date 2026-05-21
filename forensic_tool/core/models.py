"""
Core models for the Automated Digital Forensic Tool.
These models represent the central data structures used across all apps.
"""

from django.contrib.auth import get_user_model
from django.db import models
from django.utils import timezone


class SystemLog(models.Model):
    """Persistent system log entry stored in the database for the log viewer UI."""
    LEVEL_CHOICES = [
        ('DEBUG', 'Debug'),
        ('INFO', 'Info'),
        ('WARNING', 'Warning'),
        ('ERROR', 'Error'),
        ('CRITICAL', 'Critical'),
    ]
    level = models.CharField(max_length=10, choices=LEVEL_CHOICES, default='INFO')
    module = models.CharField(max_length=200, blank=True)
    message = models.TextField()
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.level}] {self.created_at:%Y-%m-%d %H:%M:%S} — {self.message[:80]}"


class InvestigatorProfile(models.Model):
    """Extended profile for investigator users — stores their official ID."""
    user = models.OneToOneField(
        get_user_model(), on_delete=models.CASCADE, related_name='profile'
    )
    investigator_id = models.CharField(max_length=50, blank=True)

    def __str__(self):
        return f"{self.user.username} — {self.investigator_id or 'No ID'}"


class DiskImage(models.Model):
    """
    Represents a registered NTFS disk image for forensic analysis.
    The image is referenced by its local file path — it is NEVER copied or stored.
    Only extracted artifacts are stored in the database.
    """

    STATUS_CHOICES = [
        ('registered', 'Registered'),
        ('validating', 'Validating'),
        ('valid', 'Valid'),
        ('invalid', 'Invalid'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    name = models.CharField(max_length=255)
    # Path to the disk image on the local filesystem — read-only, never copied
    image_path = models.TextField(unique=True)
    file_size = models.BigIntegerField(default=0)  # bytes
    sha256_hash = models.CharField(max_length=128, blank=True)  # integrity hash
    hash_algorithm = models.CharField(max_length=10, default='sha256')  # md5 / sha1 / sha256
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='registered')
    uploaded_at = models.DateTimeField(default=timezone.now)
    processed_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True)
    # Owner — the investigator who registered this image
    owner = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, related_name='disk_images', null=True)

    # Analysis progress tracking
    analysis_status = models.CharField(max_length=20, default='idle')   # idle/running/completed/failed
    analysis_progress = models.IntegerField(default=0)                  # 0–100
    analysis_label = models.CharField(max_length=100, blank=True)

    # Scoring progress tracking
    scoring_status = models.CharField(max_length=20, default='idle')    # idle/running/completed/failed
    scoring_progress = models.IntegerField(default=0)                   # 0–100
    scoring_label = models.CharField(max_length=100, blank=True)

    class Meta:
        ordering = ['-uploaded_at']

    def __str__(self):
        return f"{self.name} ({self.status})"


class ForensicArtifact(models.Model):
    """
    Represents a single forensic artifact extracted from a disk image.
    Each artifact has a source (MFT, USN, LogFile, etc.) and associated timestamps.
    """

    SOURCE_CHOICES = [
        ('MFT_SI', '$MFT STANDARD_INFORMATION'),
        ('MFT_FN', '$MFT FILE_NAME'),
        ('USN', '$UsnJrnl'),
        ('LOGFILE', '$LogFile'),
        ('REGISTRY', 'Windows Registry'),
        ('EVTX', 'Event Log (EVTX)'),
        ('VSS', 'Volume Shadow Copy'),
    ]

    # Reliability weights per source (used in evidence scoring)
    # Higher = harder to tamper with = more reliable
    SOURCE_WEIGHTS = {
        'MFT_SI': 0.6,   # Easily modified by timestomping tools
        'MFT_FN': 0.85,  # Harder to modify; requires kernel-level access
        'USN': 0.90,     # Journal entries are append-only; hard to forge
        'LOGFILE': 0.88, # Transaction log; difficult to manipulate
        'REGISTRY': 0.75,
        'EVTX': 0.80,
        'VSS': 0.95,     # Shadow copies are read-only snapshots
    }

    disk_image = models.ForeignKey(DiskImage, on_delete=models.CASCADE, related_name='artifacts')
    source = models.CharField(max_length=20, choices=SOURCE_CHOICES)
    file_path = models.TextField()           # Full path of the file in the image
    file_name = models.CharField(max_length=512)
    inode = models.BigIntegerField(null=True, blank=True)  # MFT entry number

    # MACB timestamps (all stored in UTC)
    modified_time = models.DateTimeField(null=True, blank=True)   # M
    accessed_time = models.DateTimeField(null=True, blank=True)   # A
    changed_time = models.DateTimeField(null=True, blank=True)    # C (MFT entry change)
    born_time = models.DateTimeField(null=True, blank=True)       # B (created)

    # Extra metadata
    file_size = models.BigIntegerField(null=True, blank=True)
    is_directory = models.BooleanField(default=False)
    raw_data = models.JSONField(default=dict, blank=True)  # raw parsed fields

    extracted_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['file_path', 'source']

    def __str__(self):
        return f"{self.file_name} [{self.source}]"

    @property
    def reliability_weight(self):
        """Return the reliability weight for this artifact's source."""
        return self.SOURCE_WEIGHTS.get(self.source, 0.5)


class TimelineEntry(models.Model):
    """
    A unified timeline entry combining data from multiple artifact sources.
    Used for chronological reconstruction and correlation.
    """

    EVENT_TYPES = [
        ('created', 'File Created'),
        ('modified', 'File Modified'),
        ('accessed', 'File Accessed'),
        ('changed', 'MFT Entry Changed'),
        ('deleted', 'File Deleted'),
        ('renamed', 'File Renamed'),
        ('usn_event', 'USN Journal Event'),
        ('log_event', 'LogFile Event'),
        ('registry_event', 'Registry Event'),
        ('evtx_event', 'Event Log Entry'),
    ]

    disk_image = models.ForeignKey(DiskImage, on_delete=models.CASCADE, related_name='timeline')
    artifact = models.ForeignKey(ForensicArtifact, on_delete=models.SET_NULL,
                                  null=True, blank=True, related_name='timeline_entries')
    event_time = models.DateTimeField()
    event_type = models.CharField(max_length=30, choices=EVENT_TYPES)
    source = models.CharField(max_length=20)
    file_path = models.TextField()
    file_name = models.CharField(max_length=512)
    description = models.TextField(blank=True)

    class Meta:
        ordering = ['event_time']

    def __str__(self):
        return f"{self.event_time} | {self.event_type} | {self.file_name}"


class ForgeryResult(models.Model):
    """
    Stores the forgery detection result for a specific file in a disk image.
    Contains the computed evidence score and classification.
    """

    CLASSIFICATION_CHOICES = [
        ('genuine', 'Genuine'),
        ('suspicious', 'Suspicious'),
        ('forged', 'Forged'),
    ]

    disk_image = models.ForeignKey(DiskImage, on_delete=models.CASCADE, related_name='forgery_results')
    file_path = models.TextField()
    file_name = models.CharField(max_length=512)

    # Evidence score: 0 = definitely genuine, 100 = definitely forged
    forgery_score = models.FloatField(default=0.0)
    classification = models.CharField(max_length=20, choices=CLASSIFICATION_CHOICES, default='genuine')

    # Detailed breakdown of detected anomalies
    anomalies = models.JSONField(default=list)
    scoring_breakdown = models.JSONField(default=dict)

    analyzed_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-forgery_score']

    def __str__(self):
        return f"{self.file_name} → {self.classification} ({self.forgery_score:.1f})"
