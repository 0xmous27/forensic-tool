"""Ingestion app URL configuration."""

from django.urls import path
from . import views

app_name = 'ingestion'

urlpatterns = [
    path('', views.image_list, name='image_list'),
    path('register/', views.register_image, name='register'),
    path('browse/', views.browse_filesystem, name='browse'),
    path('<int:pk>/', views.image_detail, name='image_detail'),
    path('<int:pk>/extract/', views.start_extraction, name='start_extraction'),
    path('<int:pk>/status/', views.extraction_status, name='extraction_status'),
    path('<int:pk>/delete/', views.delete_image, name='delete_image'),
]
