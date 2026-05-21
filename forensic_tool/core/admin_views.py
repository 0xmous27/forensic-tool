"""Custom admin panel views."""

from django.contrib.auth.decorators import user_passes_test
from django.contrib.auth.models import User
from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404
from django.utils import timezone
from datetime import timedelta
from core.models import SystemLog, DiskImage, ForgeryResult, InvestigatorProfile

is_staff = user_passes_test(lambda u: u.is_active and u.is_staff, login_url='/login/')


@is_staff
def admin_dashboard(request):
    now = timezone.now()
    week_ago = now - timedelta(days=7)
    context = {
        'total_investigators': User.objects.filter(is_staff=False, is_superuser=False).count(),
        'active_investigators': User.objects.filter(is_staff=False, is_superuser=False, is_active=True).count(),
        'total_logs': SystemLog.objects.count(),
        'error_logs': SystemLog.objects.filter(level__in=['ERROR', 'CRITICAL']).count(),
        'warning_logs': SystemLog.objects.filter(level='WARNING').count(),
        'recent_logs': SystemLog.objects.all()[:5],
        'recent_investigators': User.objects.filter(is_staff=False, is_superuser=False).order_by('-date_joined')[:5],
        'logs_this_week': SystemLog.objects.filter(created_at__gte=week_ago).count(),
        'new_users_this_week': User.objects.filter(is_staff=False, date_joined__gte=week_ago).count(),
    }
    return render(request, 'admin_custom/dashboard.html', context)


@is_staff
def admin_users(request):
    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'add':
            username = request.POST.get('username', '').strip()
            password = request.POST.get('password', '').strip()
            first_name = request.POST.get('first_name', '').strip()
            last_name = request.POST.get('last_name', '').strip()
            email = request.POST.get('email', '').strip()
            investigator_id = request.POST.get('investigator_id', '').strip()
            if not username or not password:
                messages.error(request, 'Username and password are required.')
            elif User.objects.filter(username=username).exists():
                messages.error(request, f'Username "{username}" already exists.')
            else:
                user = User.objects.create_user(
                    username=username, password=password,
                    first_name=first_name, last_name=last_name,
                    email=email, is_staff=False, is_superuser=False
                )
                InvestigatorProfile.objects.create(user=user, investigator_id=investigator_id)
                messages.success(request, f'Investigator "{username}" created successfully.')

        elif action == 'delete':
            user = get_object_or_404(User, pk=request.POST.get('user_id'),
                                     is_staff=False, is_superuser=False)
            username = user.username
            user.delete()
            messages.success(request, f'Investigator "{username}" deleted.')

        elif action == 'toggle_active':
            user = get_object_or_404(User, pk=request.POST.get('user_id'),
                                     is_staff=False, is_superuser=False)
            user.is_active = not user.is_active
            user.save()
            status = 'activated' if user.is_active else 'deactivated'
            messages.success(request, f'Investigator "{user.username}" {status}.')

        return redirect('admin_users')

    investigators = User.objects.filter(is_staff=False, is_superuser=False).order_by('-date_joined')
    return render(request, 'admin_custom/users.html', {'investigators': investigators})


@is_staff
def admin_user_edit(request, user_id):
    user = get_object_or_404(User, pk=user_id, is_staff=False, is_superuser=False)
    profile, _ = InvestigatorProfile.objects.get_or_create(user=user)
    if request.method == 'POST':
        user.first_name = request.POST.get('first_name', '').strip()
        user.last_name = request.POST.get('last_name', '').strip()
        user.email = request.POST.get('email', '').strip()
        new_password = request.POST.get('password', '').strip()
        if new_password:
            user.set_password(new_password)
        user.save()
        profile.investigator_id = request.POST.get('investigator_id', '').strip()
        profile.save()
        messages.success(request, f'Investigator "{user.username}" updated.')
        return redirect('admin_users')
    return render(request, 'admin_custom/user_edit.html', {'edit_user': user, 'profile': profile})


@is_staff
def admin_logs(request):
    level_filter = request.GET.get('level', '')
    date_filter = request.GET.get('date', '')
    logs = SystemLog.objects.all()
    if level_filter:
        logs = logs.filter(level=level_filter)
    if date_filter:
        logs = logs.filter(created_at__date=date_filter)
    total = logs.count()
    logs = logs[:500]
    return render(request, 'admin_custom/logs.html', {
        'logs': logs,
        'level_filter': level_filter,
        'date_filter': date_filter,
        'total': total,
        'levels': ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
    })


@is_staff
def admin_logs_clear(request):
    if request.method == 'POST':
        level = request.POST.get('level', '')
        if level:
            count, _ = SystemLog.objects.filter(level=level).delete()
            messages.success(request, f'Cleared {count} {level} log entries.')
        else:
            count, _ = SystemLog.objects.all().delete()
            messages.success(request, f'Cleared all {count} log entries.')
    return redirect('admin_logs')
