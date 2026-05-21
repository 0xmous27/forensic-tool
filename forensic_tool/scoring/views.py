"""Scoring app views."""

import logging
import threading
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.http import JsonResponse

from core.models import DiskImage, ForgeryResult
from ingestion.views import _images_for_user
from scoring.engine import ScoringEngine

logger = logging.getLogger(__name__)


@login_required
def run_scoring(request, pk):
    """Trigger evidence scoring in background thread."""
    disk_image = get_object_or_404(_images_for_user(request.user), pk=pk)

    if not ForgeryResult.objects.filter(disk_image=disk_image).exists():
        messages.error(request, 'Run correlation analysis first.')
        return redirect('ingestion:image_detail', pk=pk)

    if disk_image.scoring_status == 'running':
        messages.warning(request, 'Scoring is already running.')
        return redirect('ingestion:image_detail', pk=pk)

    disk_image.scoring_status = 'running'
    disk_image.scoring_progress = 0
    disk_image.scoring_label = 'Starting scoring...'
    disk_image.save(update_fields=['scoring_status', 'scoring_progress', 'scoring_label'])

    def _run():
        try:
            engine = ScoringEngine(disk_image)
            count = engine.run()
            disk_image.scoring_status = 'completed'
            disk_image.scoring_progress = 100
            disk_image.scoring_label = f'{count} files scored'
        except Exception as e:
            logger.error(f"Scoring failed: {e}")
            disk_image.scoring_status = 'failed'
            disk_image.scoring_label = str(e)
        finally:
            disk_image.save(update_fields=['scoring_status', 'scoring_progress', 'scoring_label'])

    threading.Thread(target=_run, daemon=True).start()
    messages.info(request, 'Scoring started in background.')
    return redirect('ingestion:image_detail', pk=pk)


@login_required
def scoring_status(request, pk):
    """AJAX: return current scoring progress."""
    disk_image = get_object_or_404(_images_for_user(request.user), pk=pk)
    disk_image.refresh_from_db()
    return JsonResponse({
        'status': disk_image.scoring_status,
        'progress': disk_image.scoring_progress,
        'label': disk_image.scoring_label,
    })


@login_required
def scoring_summary(request, pk):
    """Display scoring summary statistics for a disk image."""
    disk_image = get_object_or_404(_images_for_user(request.user), pk=pk)
    results = ForgeryResult.objects.filter(disk_image=disk_image)

    forged = results.filter(classification='forged')
    suspicious = results.filter(classification='suspicious')
    genuine = results.filter(classification='genuine')

    # Top 10 most suspicious files
    top_suspicious = results.order_by('-forgery_score')[:10]

    context = {
        'disk_image': disk_image,
        'total': results.count(),
        'forged_count': forged.count(),
        'suspicious_count': suspicious.count(),
        'genuine_count': genuine.count(),
        'top_suspicious': top_suspicious,
    }
    return render(request, 'scoring/summary.html', context)
