"""Analysis app URL configuration."""

from django.urls import path
from . import views

app_name = 'analysis'

urlpatterns = [
    path('<int:pk>/run/', views.run_analysis, name='run_analysis'),
    path('<int:pk>/status/', views.analysis_status, name='analysis_status'),
    path('<int:pk>/timeline/', views.timeline_view, name='timeline'),
    path('<int:pk>/timeline/data/', views.timeline_chart_data, name='timeline_chart_data'),
    path('<int:pk>/results/', views.forgery_results, name='forgery_results'),
    path('<int:pk>/results/charts/', views.forgery_chart_data, name='forgery_chart_data'),
    path('<int:pk>/results/<int:result_pk>/', views.file_detail, name='file_detail'),
]
