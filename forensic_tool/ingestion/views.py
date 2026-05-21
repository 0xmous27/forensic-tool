"""
Ingestion app views.

Disk images are registered by local file path — they are NEVER uploaded or copied.
Only extracted artifacts are stored in the database.
"""

import os
import logging
import threading

from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.utils import timezone
from django.http import JsonResponse

from core.models import DiskImage
from ingestion.models import ExtractionJob
from ingestion.services import NTFSExtractor, EWFExtractor, compute_hash_by_algorithm

logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = ('.img', '.dd', '.raw', '.e01', '.E01', '.001', '.vmdk')


def _is_ewf(path: str) -> bool:
    return path.lower().endswith('.e01')


def _images_for_user(user):
    """Return DiskImage queryset scoped to the user. Admins see all."""
    if user.is_staff or user.is_superuser:
        return DiskImage.objects.all()
    return DiskImage.objects.filter(owner=user)


@login_required
def register_image(request):
    """Register a disk image by its local file path (no upload/copy)."""
    if request.method == 'POST':
        image_path = request.POST.get('image_path', '').strip()
        hash_algorithm = request.POST.get('hash_algorithm', 'sha256').lower()
        expected_hash = request.POST.get('expected_hash', '').strip().lower()

        if hash_algorithm not in ('md5', 'sha1', 'sha256'):
            hash_algorithm = 'sha256'

        if not image_path:
            messages.error(request, 'Please provide a file path.')
            return redirect('ingestion:register')

        if not expected_hash:
            messages.error(request, f'Please enter the expected {hash_algorithm.upper()} hash for integrity verification.')
            return redirect('ingestion:register')

        if not os.path.isfile(image_path):
            messages.error(request, f'File not found: {image_path}')
            return redirect('ingestion:register')

        if not any(image_path.lower().endswith(ext.lower()) for ext in ALLOWED_EXTENSIONS):
            messages.error(request, f'Unsupported format. Allowed: {", ".join(ALLOWED_EXTENSIONS)}')
            return redirect('ingestion:register')

        if not os.access(image_path, os.R_OK):
            messages.error(request, f'File is not readable: {image_path}')
            return redirect('ingestion:register')

        if DiskImage.objects.filter(image_path=image_path).exists():
            existing = DiskImage.objects.get(image_path=image_path)
            if existing.owner is None:
                # Legacy record with no owner — claim it for this investigator
                existing.owner = request.user
                existing.save(update_fields=['owner'])
                messages.warning(request, 'Image already registered. Assigned to your account.')
                return redirect('ingestion:image_detail', pk=existing.pk)
            elif existing.owner == request.user:
                messages.warning(request, 'You have already registered this image.')
                return redirect('ingestion:image_detail', pk=existing.pk)
            else:
                messages.error(request,
                    'This disk image path is already assigned to another investigator\'s case. '
                    'Each disk image can only be registered by one investigator. '
                    'Please use a separate copy of the evidence file for your case.'
                )
                return redirect('ingestion:register')

        file_size = os.path.getsize(image_path)
        name = os.path.basename(image_path)

        disk_image = DiskImage.objects.create(
            name=name,
            image_path=image_path,
            file_size=file_size,
            status='validating',
            hash_algorithm=hash_algorithm,
            notes=f'Hashing with {hash_algorithm.upper()}...',
            owner=request.user,
        )

        def compute_hash():
            try:
                if _is_ewf(image_path):
                    extractor = EWFExtractor(disk_image)
                    digest, _ = extractor.verify_integrity()
                    digest = digest or ''
                else:
                    digest = compute_hash_by_algorithm(image_path, hash_algorithm)

                disk_image.sha256_hash = digest

                if digest.lower() == expected_hash:
                    disk_image.status = 'valid'
                    disk_image.notes = (
                        f'{hash_algorithm.upper()} verified: hash matches. '
                        f'Image integrity confirmed.'
                    )
                    logger.info(f"Hash verified for {name}: {hash_algorithm.upper()}={digest}")
                else:
                    disk_image.status = 'invalid'
                    disk_image.notes = (
                        f'HASH MISMATCH — {hash_algorithm.upper()} verification failed. '
                        f'Computed: {digest} | Expected: {expected_hash}. '
                        f'The image may be corrupted or tampered with. '
                        f'Please provide a valid disk image.'
                    )
                    logger.warning(
                        f"Hash mismatch for {name}: computed={digest}, expected={expected_hash}"
                    )

                disk_image.save(update_fields=['sha256_hash', 'status', 'notes'])
            except Exception as e:
                disk_image.status = 'invalid'
                disk_image.notes = str(e)
                disk_image.save(update_fields=['status', 'notes'])

        threading.Thread(target=compute_hash, daemon=True).start()

        messages.success(request, f'Image "{name}" registered. Verifying {hash_algorithm.upper()} hash...')
        return redirect('ingestion:image_detail', pk=disk_image.pk)

    return render(request, 'ingestion/register.html', {'allowed': ALLOWED_EXTENSIONS})


@login_required
def image_detail(request, pk):
    disk_image = get_object_or_404(_images_for_user(request.user), pk=pk)
    job = ExtractionJob.objects.filter(disk_image=disk_image).first()
    from core.models import ForgeryResult
    has_analysis = ForgeryResult.objects.filter(disk_image=disk_image).exists()
    has_scoring = ForgeryResult.objects.filter(disk_image=disk_image, forgery_score__gt=0).exists()
    return render(request, 'ingestion/image_detail.html', {
        'disk_image': disk_image,
        'job': job,
        'is_ewf': _is_ewf(disk_image.image_path),
        'has_analysis': has_analysis,
        'has_scoring': has_scoring,
    })


@login_required
def start_extraction(request, pk):
    disk_image = get_object_or_404(_images_for_user(request.user), pk=pk)

    if disk_image.status not in ('valid', 'completed'):
        messages.error(request, 'Image must be validated before extraction.')
        return redirect('ingestion:image_detail', pk=pk)

    job, _ = ExtractionJob.objects.get_or_create(disk_image=disk_image)
    job.status = 'pending'
    job.log = ''
    job.artifacts_extracted = 0
    job.error_message = ''
    job.current_step = 0
    job.total_steps = 6   # 5 extraction steps + 1 timeline
    job.current_step_label = 'Initialising...'
    job.save()

    disk_image.status = 'processing'
    disk_image.save(update_fields=['status'])

    def run_extraction():
        job.status = 'running'
        job.started_at = timezone.now()
        job.save(update_fields=['status', 'started_at'])
        try:
            extractor = EWFExtractor(disk_image) if _is_ewf(disk_image.image_path) else NTFSExtractor(disk_image)
            count = extractor.extract_all(job)
            job.status = 'completed'
            job.artifacts_extracted = count
            job.finished_at = timezone.now()
            job.current_step = job.total_steps
            job.current_step_label = 'Completed'
            disk_image.status = 'completed'
            disk_image.processed_at = timezone.now()
        except Exception as e:
            logger.error(f"Extraction failed for {disk_image.name}: {e}")
            job.status = 'failed'
            job.error_message = str(e)
            disk_image.status = 'failed'
        finally:
            job.save()
            disk_image.save(update_fields=['status', 'processed_at'])

    threading.Thread(target=run_extraction, daemon=True).start()
    messages.info(request, 'Extraction started in background.')
    return redirect('ingestion:image_detail', pk=pk)


@login_required
def extraction_status(request, pk):
    """AJAX: return current extraction job status including progress and hash status."""
    disk_image = get_object_or_404(_images_for_user(request.user), pk=pk)
    job = ExtractionJob.objects.filter(disk_image=disk_image).first()

    # Refresh disk_image from DB to get latest hash/status
    disk_image.refresh_from_db()

    eta_seconds = None
    if job and job.status == 'running' and job.started_at and job.current_step > 0:
        elapsed = (timezone.now() - job.started_at).total_seconds()
        rate = job.current_step / elapsed if elapsed > 0 else 0
        remaining = job.total_steps - job.current_step
        eta_seconds = int(remaining / rate) if rate > 0 else None

    return JsonResponse({
        'status': job.status if job else 'no_job',
        'artifacts_extracted': job.artifacts_extracted if job else 0,
        'log': job.log[-3000:] if job else '',
        'image_status': disk_image.status,
        'sha256_hash': disk_image.sha256_hash,
        'notes': disk_image.notes,
        'progress': job.progress_percent if job else 0,
        'current_step': job.current_step if job else 0,
        'total_steps': job.total_steps if job else 6,
        'current_step_label': job.current_step_label if job else '',
        'eta_seconds': eta_seconds,
    })


@login_required
def image_list(request):
    from core.models import ForgeryResult
    images = _images_for_user(request.user).order_by('-uploaded_at')
    context = {
        'images': images,
        'total': images.count(),
        'completed': images.filter(status='completed').count(),
        'processing': images.filter(status__in=['processing', 'validating']).count(),
        'failed': images.filter(status__in=['failed', 'invalid']).count(),
    }
    return render(request, 'ingestion/image_list.html', context)


@login_required
def delete_image(request, pk):
    disk_image = get_object_or_404(_images_for_user(request.user), pk=pk)
    if request.method == 'POST':
        disk_image.delete()
        messages.success(request, 'Image registration deleted. Original file was not modified.')
        return redirect('ingestion:image_list')
    return render(request, 'ingestion/confirm_delete.html', {'disk_image': disk_image})


@login_required
def browse_filesystem(request):
    """AJAX: Browse server filesystem to help investigator find disk images."""
    path = request.GET.get('path', '/home').strip()
    
    if not os.path.isabs(path):
        path = '/home'
    
    if not os.path.exists(path):
        return JsonResponse({'error': 'Path does not exist'}, status=400)
    
    if not os.path.isdir(path):
        return JsonResponse({'error': 'Not a directory'}, status=400)
    
    try:
        entries = []
        for name in sorted(os.listdir(path)):
            if name.startswith('.'):
                continue
            full_path = os.path.join(path, name)
            try:
                is_dir = os.path.isdir(full_path)
                is_image = any(name.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS)

                if is_dir or is_image:
                    entries.append({
                        'name': name,
                        'path': full_path,
                        'is_dir': is_dir,
                        'is_image': is_image,
                        'size': os.path.getsize(full_path) if not is_dir else 0,
                    })
            except (PermissionError, OSError):
                continue

        parent = os.path.dirname(path) if path != '/' else None

        # Build breadcrumb parts from path
        parts = [p for p in path.split('/') if p]
        breadcrumbs = [{'name': '/', 'path': '/'}]
        for i, part in enumerate(parts):
            breadcrumbs.append({'name': part, 'path': '/' + '/'.join(parts[:i + 1])})

        return JsonResponse({
            'current_path': path,
            'parent': parent,
            'breadcrumbs': breadcrumbs,
            'entries': entries,
        })
    except PermissionError:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
