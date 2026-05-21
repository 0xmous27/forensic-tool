"""Core views: dashboard, about, and system log viewer."""

from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from core.models import DiskImage, ForgeryResult, SystemLog


def role_login(request):
    if request.user.is_authenticated:
        return _role_redirect(request.user)
    if request.method == 'POST':
        user = authenticate(request,
                            username=request.POST.get('username'),
                            password=request.POST.get('password'))
        if user:
            login(request, user)
            next_url = request.GET.get('next') or request.POST.get('next')
            return redirect(next_url) if next_url else _role_redirect(user)
        return render(request, 'core/login.html', {'error': 'Invalid credentials'})
    return render(request, 'core/login.html')


def _role_redirect(user):
    if user.is_superuser or user.is_staff:
        return redirect('/admin-panel/')
    return redirect('/ingestion/')


@login_required
def dashboard(request):
    user = request.user
    if user.is_staff or user.is_superuser:
        images = DiskImage.objects.all()[:10]
        qs = DiskImage.objects
        fq = ForgeryResult.objects
    else:
        images = DiskImage.objects.filter(owner=user)[:10]
        qs = DiskImage.objects.filter(owner=user)
        fq = ForgeryResult.objects.filter(disk_image__owner=user)

    context = {
        'images': images,
        'total_images': qs.count(),
        'completed': qs.filter(status='completed').count(),
        'forged_count': fq.filter(classification='forged').count(),
        'suspicious_count': fq.filter(classification='suspicious').count(),
    }
    return render(request, 'core/dashboard.html', context)


@login_required
def about(request):
    return render(request, 'core/about.html')


@login_required
def system_logs(request):
    """System log viewer — shows persistent DB-stored log entries."""
    level_filter = request.GET.get('level', '')
    logs = SystemLog.objects.all()
    if level_filter:
        logs = logs.filter(level=level_filter)
    logs = logs[:500]  # cap at 500 most recent
    return render(request, 'core/system_logs.html', {
        'logs': logs,
        'level_filter': level_filter,
        'levels': ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
    })


def current_image_context(request):
    """Inject current disk image pk into all templates for sidebar links."""
    pk = None
    if hasattr(request, 'resolver_match') and request.resolver_match:
        pk = request.resolver_match.kwargs.get('pk')
    return {'current_image_pk': pk}
