"""Main URL configuration for the forensic tool."""

from django.contrib.auth import views as auth_views
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView
from core.admin_views import (
    admin_dashboard, admin_users, admin_user_edit,
    admin_logs, admin_logs_clear,
)
from core.views import role_login

urlpatterns = [
    path('django-admin/', RedirectView.as_view(url='/admin-panel/', permanent=False)),
    path('login/', role_login, name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    # Custom admin panel
    path('admin-panel/', admin_dashboard, name='admin_dashboard'),
    path('admin-panel/users/', admin_users, name='admin_users'),
    path('admin-panel/users/<int:user_id>/edit/', admin_user_edit, name='admin_user_edit'),
    path('admin-panel/logs/', admin_logs, name='admin_logs'),
    path('admin-panel/logs/clear/', admin_logs_clear, name='admin_logs_clear'),
    # Apps
    path('', include('core.urls')),
    path('ingestion/', include('ingestion.urls')),
    path('analysis/', include('analysis.urls')),
    path('scoring/', include('scoring.urls')),
    path('reporting/', include('reporting.urls')),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
