"""Reporting app views: generate and download PDF/HTML reports."""

import logging
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse, Http404
from django.contrib import messages
from ingestion.views import _images_for_user
from core.models import DiskImage

from core.models import DiskImage
from reporting.services import generate_pdf_report, generate_html_report

logger = logging.getLogger(__name__)


@login_required
def report_index(request, pk):
    """Report generation page for a disk image."""
    disk_image = get_object_or_404(_images_for_user(request.user), pk=pk)
    return render(request, 'reporting/report_index.html', {'disk_image': disk_image})


@login_required
def download_pdf(request, pk):
    disk_image = get_object_or_404(_images_for_user(request.user), pk=pk)
    try:
        pdf_bytes = generate_pdf_report(disk_image, investigator=request.user)
        filename = f"forensic_report_{disk_image.name.replace(' ', '_')}.pdf"
        response = HttpResponse(pdf_bytes, content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        messages.error(request, f'PDF generation failed: {e}')
        return render(request, 'reporting/report_index.html', {'disk_image': disk_image})


@login_required
def view_html_report(request, pk):
    disk_image = get_object_or_404(_images_for_user(request.user), pk=pk)
    try:
        html_content = generate_html_report(disk_image, investigator=request.user)
        return HttpResponse(html_content)
    except Exception as e:
        logger.error(f"HTML report generation failed: {e}")
        raise Http404(f"Report generation failed: {e}")


@login_required
def download_html(request, pk):
    disk_image = get_object_or_404(_images_for_user(request.user), pk=pk)
    try:
        html_content = generate_html_report(disk_image, investigator=request.user)
        filename = f"forensic_report_{disk_image.name.replace(' ', '_')}.html"
        response = HttpResponse(html_content, content_type='text/html')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
    except Exception as e:
        logger.error(f"HTML download failed: {e}")
        messages.error(request, f'HTML report generation failed: {e}')
        return render(request, 'reporting/report_index.html', {'disk_image': disk_image})
