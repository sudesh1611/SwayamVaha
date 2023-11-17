"""
URL configuration for dashboard project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from . import views
from django.contrib import admin
from django.urls import path, include
from rest_framework import routers

router = routers.DefaultRouter()
router.register(r'cve', views.CveViewSet)
router.register(r'false-positive', views.FalsePositiveViewSet)
router.register(r'scan-report', views.ScanReportViewSet)
router.register(r'report-detail', views.ReportDetailsViewSet)

urlpatterns = [
    path('', views.home, name='home'),
    path('api/report-detail/by-package-name', views.ReportDetailsViewSet.as_view({'get': 'sort_by_package_name'}), name='by-package-name'),
    path('api/report-detail/by-cvss', views.ReportDetailsViewSet.as_view({'get': 'sort_by_package_cvss'}), name='by-cvss'),
    path('api/report-detail/versions-from-scan-type', views.ReportDetailsViewSet.as_view({'get': 'get_versions_from_scan_type'}), name='versions-from-scan-type'),
    path('api/report-detail/scans-from-version-and-scan_type', views.ReportDetailsViewSet.as_view({'get': 'get_date_time_user_from_version_and_scan_type'}), name='scans-from-version-and-scan_type'),
    path('api/report-detail/images-from-scan-id', views.ReportDetailsViewSet.as_view({'get': 'get_image_names_from_scan_id'}), name='images-from-scan-id'),
    path('api/report-detail/compare-report-results', views.ReportDetailsViewSet.as_view({'get': 'compare_reports'}), name='compare-report-results'),
    path('api/', include(router.urls)),
    path('admin/', admin.site.urls),
    path('download-file/', views.download_file, name='download-file'),
    path('login/', views.login_user, name='login'),
    path('logout/', views.logout_user, name='logout'),
    path('page-not-found/', views.page_not_found, name='page-not-found'),
    path('all-scans/', views.all_scans, name='all-scans'),
    path('scan-details/', views.scan_details, name="scan-details"),
    path('report-details/', views.report_details, name="report-details"),
    path('compare-reports/', views.compare_reports, name="compare-reports")
]
