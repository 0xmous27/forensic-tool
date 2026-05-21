"""Scoring app URL configuration."""

from django.urls import path
from . import views

app_name = 'scoring'

urlpatterns = [
    path('<int:pk>/run/', views.run_scoring, name='run_scoring'),
    path('<int:pk>/status/', views.scoring_status, name='scoring_status'),
    path('<int:pk>/summary/', views.scoring_summary, name='summary'),
]
