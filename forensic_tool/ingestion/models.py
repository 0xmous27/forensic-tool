"""
Ingestion app models.
Tracks extraction job status including real-time progress for the UI progress bar.
"""

from django.db import models
from core.models import DiskImage


class ExtractionJob(models.Model):
    """Tracks the status and progress of an artifact extraction job."""

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    disk_image = models.OneToOneField(DiskImage, on_delete=models.CASCADE, related_name='extraction_job')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    artifacts_extracted = models.IntegerField(default=0)
    error_message = models.TextField(blank=True)
    log = models.TextField(blank=True)

    # Progress tracking for the real-time progress bar
    current_step = models.IntegerField(default=0)   # steps completed
    total_steps = models.IntegerField(default=5)    # total pipeline steps
    current_step_label = models.CharField(max_length=100, blank=True)

    def __str__(self):
        return f"Job for {self.disk_image.name} [{self.status}]"

    @property
    def progress_percent(self):
        if self.total_steps == 0:
            return 0
        return min(int(self.current_step / self.total_steps * 100), 100)
