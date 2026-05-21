"""Core app URL configuration."""

from django.urls import path
from . import views

app_name = 'core'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('about/', views.about, name='about'),
    path('logs/', views.system_logs, name='system_logs'),
]
