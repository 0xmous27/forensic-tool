"""Reporting app URL configuration."""

from django.urls import path
from . import views

app_name = 'reporting'

urlpatterns = [
    path('<int:pk>/', views.report_index, name='report_index'),
    path('<int:pk>/pdf/', views.download_pdf, name='download_pdf'),
    path('<int:pk>/html/', views.view_html_report, name='view_html'),
    path('<int:pk>/html/download/', views.download_html, name='download_html'),
]
