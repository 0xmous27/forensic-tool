"""
core/admin.py — Django admin configuration.
Only superusers can access /django-admin/.
Investigators are managed here by the admin.
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User
from django.http import HttpResponseRedirect
from .models import DiskImage, ForensicArtifact, TimelineEntry, ForgeryResult, SystemLog


# ── Block non-superusers from Django admin ──────────────────────────────────

class SuperuserOnlyAdminSite(admin.AdminSite):
    def has_permission(self, request):
        return request.user.is_active and request.user.is_superuser


admin_site = SuperuserOnlyAdminSite(name='admin')


# ── Investigator (User) management ──────────────────────────────────────────

class InvestigatorAdmin(UserAdmin):
    """Manage investigator accounts — non-staff users only."""

    list_display = ('id', 'username', 'get_full_name', 'email', 'role', 'is_active', 'date_joined')
    list_filter = ('is_active', 'date_joined')
    search_fields = ('username', 'first_name', 'last_name', 'email')
    ordering = ('-date_joined',)

    # Fieldsets shown when editing a user
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'email')}),
        ('Status', {'fields': ('is_active',)}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'password1', 'password2', 'first_name', 'last_name', 'email'),
        }),
    )

    def get_queryset(self, request):
        # Only show non-staff users (investigators)
        return super().get_queryset(request).filter(is_staff=False, is_superuser=False)

    def save_model(self, request, obj, form, change):
        # Ensure created users are never staff/superuser
        obj.is_staff = False
        obj.is_superuser = False
        super().save_model(request, obj, form, change)

    def role(self, obj):
        return 'Investigator'
    role.short_description = 'Role'


admin_site.register(User, InvestigatorAdmin)


# ── System Logs ──────────────────────────────────────────────────────────────

@admin.register(SystemLog, site=admin_site)
class SystemLogAdmin(admin.ModelAdmin):
    list_display = ('created_at', 'level', 'module', 'short_message')
    list_filter = ('level', 'created_at')
    search_fields = ('message', 'module')
    ordering = ('-created_at',)
    readonly_fields = ('level', 'module', 'message', 'created_at')

    def short_message(self, obj):
        return obj.message[:100]
    short_message.short_description = 'Message'

    def has_add_permission(self, request):
        return False  # logs are system-generated only

    def has_change_permission(self, request, obj=None):
        return False


# ── Forensic models ──────────────────────────────────────────────────────────

@admin.register(DiskImage, site=admin_site)
class DiskImageAdmin(admin.ModelAdmin):
    list_display = ('name', 'status', 'file_size', 'uploaded_at')
    list_filter = ('status',)
    search_fields = ('name', 'image_path')


@admin.register(ForgeryResult, site=admin_site)
class ForgeryResultAdmin(admin.ModelAdmin):
    list_display = ('file_name', 'classification', 'forgery_score', 'analyzed_at')
    list_filter = ('classification',)
    search_fields = ('file_name',)


admin_site.register(ForensicArtifact)
admin_site.register(TimelineEntry)
