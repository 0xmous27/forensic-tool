"""Analysis app views: timeline, correlation, and file detail."""

import json
import logging
import threading

from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.http import JsonResponse
from django.core.paginator import Paginator

from core.models import DiskImage, ForensicArtifact, TimelineEntry, ForgeryResult
from analysis.correlation import CorrelationEngine
from ingestion.views import _images_for_user

logger = logging.getLogger(__name__)


@login_required
def run_analysis(request, pk):
    """Trigger correlation analysis in background thread."""
    disk_image = get_object_or_404(_images_for_user(request.user), pk=pk)
    if disk_image.status != 'completed':
        messages.error(request, 'Extraction must be completed before analysis.')
        return redirect('ingestion:image_detail', pk=pk)

    if disk_image.analysis_status == 'running':
        messages.warning(request, 'Analysis is already running.')
        return redirect('ingestion:image_detail', pk=pk)

    disk_image.analysis_status = 'running'
    disk_image.analysis_progress = 0
    disk_image.analysis_label = 'Starting analysis...'
    disk_image.save(update_fields=['analysis_status', 'analysis_progress', 'analysis_label'])

    def _run():
        try:
            engine = CorrelationEngine(disk_image)
            count = engine.run()
            disk_image.analysis_status = 'completed'
            disk_image.analysis_progress = 100
            disk_image.analysis_label = f'{count} files analyzed'
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            disk_image.analysis_status = 'failed'
            disk_image.analysis_label = str(e)
        finally:
            disk_image.save(update_fields=['analysis_status', 'analysis_progress', 'analysis_label'])

    threading.Thread(target=_run, daemon=True).start()
    messages.info(request, 'Analysis started in background.')
    return redirect('ingestion:image_detail', pk=pk)


@login_required
def analysis_status(request, pk):
    """AJAX: return current analysis progress."""
    disk_image = get_object_or_404(_images_for_user(request.user), pk=pk)
    disk_image.refresh_from_db()
    return JsonResponse({
        'status': disk_image.analysis_status,
        'progress': disk_image.analysis_progress,
        'label': disk_image.analysis_label,
    })


@login_required
def timeline_view(request, pk):
    """
    Display the unified forensic timeline with filtering options.
    Supports filtering by file name, date range, and artifact source.
    """
    disk_image = get_object_or_404(_images_for_user(request.user), pk=pk)
    entries = TimelineEntry.objects.filter(disk_image=disk_image)

    # --- Filtering ---
    file_name_filter = request.GET.get('file_name', '').strip()
    source_filter = request.GET.get('source', '').strip()
    date_from = request.GET.get('date_from', '').strip()
    date_to = request.GET.get('date_to', '').strip()

    if file_name_filter:
        entries = entries.filter(file_name__icontains=file_name_filter)
    if source_filter:
        entries = entries.filter(source=source_filter)
    if date_from:
        entries = entries.filter(event_time__gte=date_from)
    if date_to:
        entries = entries.filter(event_time__lte=date_to)

    # Paginate
    paginator = Paginator(entries, 50)
    page_obj = paginator.get_page(request.GET.get('page'))

    # Source choices for filter dropdown
    source_choices = ForensicArtifact.SOURCE_CHOICES

    context = {
        'disk_image': disk_image,
        'page_obj': page_obj,
        'total_entries': entries.count(),
        'source_choices': source_choices,
        'filters': {
            'file_name': file_name_filter,
            'source': source_filter,
            'date_from': date_from,
            'date_to': date_to,
        },
    }
    return render(request, 'analysis/timeline.html', context)


@login_required
def timeline_chart_data(request, pk):
    """
    AJAX endpoint: return timeline data as JSON for Plotly chart rendering.
    Returns event counts grouped by date and source.
    """
    disk_image = get_object_or_404(_images_for_user(request.user), pk=pk)
    entries = TimelineEntry.objects.filter(disk_image=disk_image).order_by('event_time')

    # Group by date and source
    from collections import defaultdict
    data = defaultdict(lambda: defaultdict(int))
    for entry in entries[:5000]:  # Limit for performance
        date_str = entry.event_time.strftime('%Y-%m-%d')
        data[date_str][entry.source] += 1

    return JsonResponse({'timeline_data': dict(data)})


@login_required
def forgery_results(request, pk):
    """Display forgery detection results for a disk image."""
    disk_image = get_object_or_404(_images_for_user(request.user), pk=pk)
    results = ForgeryResult.objects.filter(disk_image=disk_image)

    # Filter by classification
    classification_filter = request.GET.get('classification', '').strip()
    if classification_filter:
        results = results.filter(classification=classification_filter)

    # Filter by file name
    file_name_filter = request.GET.get('file_name', '').strip()
    if file_name_filter:
        results = results.filter(file_name__icontains=file_name_filter)

    paginator = Paginator(results, 50)
    page_obj = paginator.get_page(request.GET.get('page'))

    # Summary counts
    total = ForgeryResult.objects.filter(disk_image=disk_image).count()
    forged = ForgeryResult.objects.filter(disk_image=disk_image, classification='forged').count()
    suspicious = ForgeryResult.objects.filter(disk_image=disk_image, classification='suspicious').count()
    genuine = ForgeryResult.objects.filter(disk_image=disk_image, classification='genuine').count()

    context = {
        'disk_image': disk_image,
        'page_obj': page_obj,
        'total': total,
        'forged': forged,
        'suspicious': suspicious,
        'genuine': genuine,
        'filters': {
            'classification': classification_filter,
            'file_name': file_name_filter,
        },
    }
    return render(request, 'analysis/forgery_results.html', context)


@login_required
def forgery_chart_data(request, pk):
    """AJAX: chart data for forgery results visualizations."""
    from collections import defaultdict
    disk_image = get_object_or_404(_images_for_user(request.user), pk=pk)
    results = ForgeryResult.objects.filter(disk_image=disk_image)

    # 1. Classification counts (bar + pie)
    forged = results.filter(classification='forged').count()
    suspicious = results.filter(classification='suspicious').count()
    genuine = results.filter(classification='genuine').count()

    # 2. Score distribution buckets (histogram) 0-10,10-20,...,90-100
    buckets = [0] * 10
    for r in results.values_list('forgery_score', flat=True):
        idx = min(int(r // 10), 9)
        buckets[idx] += 1

    # 3. Timeline: events per day coloured by classification
    timeline_data = defaultdict(lambda: {'forged': 0, 'suspicious': 0, 'genuine': 0})
    for r in results.filter(analyzed_at__isnull=False).values('analyzed_at', 'classification'):
        day = r['analyzed_at'].strftime('%Y-%m-%d')
        timeline_data[day][r['classification']] += 1

    # 4. Heatmap: hour vs weekday activity from timeline entries
    heatmap = defaultdict(int)
    for e in TimelineEntry.objects.filter(disk_image=disk_image).values_list('event_time', flat=True)[:10000]:
        heatmap[f"{e.weekday()},{e.hour}"] += 1

    # Build heatmap matrix [weekday][hour]
    hm_matrix = [[0]*24 for _ in range(7)]
    for key, val in heatmap.items():
        wd, hr = map(int, key.split(','))
        hm_matrix[wd][hr] = val

    # 5. Top 20 scores for scatter
    top = list(results.order_by('-forgery_score')[:20].values('file_name', 'forgery_score', 'classification'))

    sorted_days = sorted(timeline_data.keys())

    return JsonResponse({
        'classification': {'forged': forged, 'suspicious': suspicious, 'genuine': genuine},
        'score_buckets': buckets,
        'timeline': {
            'days': sorted_days,
            'forged':     [timeline_data[d]['forged'] for d in sorted_days],
            'suspicious': [timeline_data[d]['suspicious'] for d in sorted_days],
            'genuine':    [timeline_data[d]['genuine'] for d in sorted_days],
        },
        'heatmap': hm_matrix,
        'top_scores': top,
    })


@login_required
def file_detail(request, pk, result_pk):
    """Show detailed analysis for a single file."""
    disk_image = get_object_or_404(_images_for_user(request.user), pk=pk)
    result = get_object_or_404(ForgeryResult, pk=result_pk, disk_image=disk_image)

    # Get all artifacts for this file
    artifacts = ForensicArtifact.objects.filter(
        disk_image=disk_image,
        file_path=result.file_path
    )

    # Get timeline entries for this file
    timeline = TimelineEntry.objects.filter(
        disk_image=disk_image,
        file_path=result.file_path
    ).order_by('event_time')

    context = {
        'disk_image': disk_image,
        'result': result,
        'artifacts': artifacts,
        'timeline': timeline,
        'anomalies': result.anomalies,
        'scoring_breakdown': result.scoring_breakdown,
    }
    return render(request, 'analysis/file_detail.html', context)
