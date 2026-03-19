# apps/reports/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('create/', views.CreateReportView.as_view(), name='create-report'),
    path('track/<str:tracking_number>/', views.TrackReportView.as_view(), name='track-report'),
    path('my-reports/', views.MyReportsView.as_view(), name='my-reports'),
    path('<uuid:pk>/', views.ReportDetailView.as_view(), name='report-detail'),
    path('<uuid:pk>/comments/', views.AddCommentView.as_view(), name='add-comment'),
    
    # مسارات المشرفين
    path('admin/list/', views.AdminReportListView.as_view(), name='admin-report-list'),
    path('admin/<uuid:pk>/update-status/', views.UpdateReportStatusView.as_view(), name='update-report-status'),
    path('admin/stats/', views.ReportStatsView.as_view(), name='report-stats'),
    
    # حذف البلاغات (Soft Delete)
    path('<uuid:pk>/delete-soft/', views.DeleteReportSoftView.as_view(), name='report-delete-soft'),
    path('clear-all-soft/', views.DeleteAllReportsSoftView.as_view(), name='report-clear-all-soft'),
    path('<uuid:pk>/restore/', views.RestoreReportSoftView.as_view(), name='report-restore-soft'),
    path('restore-bulk-soft/', views.RestoreReportsBulkView.as_view(), name='report-restore-bulk-soft'),
]