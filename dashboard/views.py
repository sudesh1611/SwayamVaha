from .core.configs import BlackduckProjectConfig, TwistlockProjectConfig, WebAppConfig
from .core.constants import GlobalConstants, ScanReportConstants, WebAppConstants
from .core.helpers.datetimeconverter import parse_common_date, parse_common_time
from .core.logger import Logger
from .core.report import PdfReport
from .models import Cve, FalsePositive, ScanReport
from .serializers import CveSerializer, FalsePositiveSerializer, ScanReportSerializer
from .utilities import DisplayResult, check_if_false_positive, get_scan_result_by_id, get_scan_result_by_version, get_all_scans_collected_by_type
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.http import HttpResponse, FileResponse
from django.shortcuts import render, redirect
from rest_framework import status, permissions, viewsets, authentication
from rest_framework.decorators import action
from rest_framework.response import Response
from typing import Dict, List, Any

import json
import os
import traceback
import uuid


class CveViewSet(viewsets.ModelViewSet):
    authentication_classes = [authentication.SessionAuthentication, authentication.BasicAuthentication]
    queryset = Cve.objects.all()
    serializer_class = CveSerializer
    http_method_names = [GlobalConstants.GET, GlobalConstants.POST]
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    logger: Logger = Logger(WebAppConfig.LOG_FILE_PATH)
    def create(self, request, *args, **kwargs):
        data: Dict[str, Any] = request.data
        try:
            self.logger.info(f"Start CveViewSet Create. Data -> {json.dumps(data, indent=4)}")
            cve_id: str = data.get(WebAppConstants.CVE_ID)
            jira: str = data.get(WebAppConstants.JIRAS)
            jira_status: str = data.get(WebAppConstants.JIRA_STATUS)
            jira_summary: str = data.get(WebAppConstants.JIRA_SUMMARY)
            if cve_id is None or jira is None:
                self.logger.error("CVE ID or Jira ID is null")
                return Response({GlobalConstants.ERROR_CAPS: "CVE ID or Jira ID is null"}, status=status.HTTP_400_BAD_REQUEST)
            if Cve.objects.filter(cve_id=cve_id.upper()).exists():
                cve = Cve.objects.get(cve_id=cve_id.upper())
                cve.add_jira_list(jira.upper(), jira_status, jira_summary)
                cve.save()
            else:
                cve = Cve()
                cve.cve_id=cve_id.upper()
                cve.add_jira_list(jira.upper(), jira_status, jira_summary)
                cve.save()
            self.logger.info(f"End CveViewSet Create. Success")
            return Response(status=status.HTTP_200_OK)
        except Exception as ex:
            self.logger.error(f"Exception ({ex}) occured in CveViewSet Create")
            self.logger.error(traceback.format_exc())
            return Response({GlobalConstants.ERROR_CAPS: ex}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class FalsePositiveViewSet(viewsets.ModelViewSet):
    authentication_classes = [authentication.SessionAuthentication, authentication.BasicAuthentication]
    queryset = FalsePositive.objects.all()
    serializer_class = FalsePositiveSerializer
    http_method_names = [GlobalConstants.GET, GlobalConstants.POST]
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    logger: Logger = Logger(WebAppConfig.LOG_FILE_PATH)

    def create(self, request, *args, **kwargs):
        data: Dict[str, Any] = request.data
        try:
            self.logger.info(f"Start FalsePositiveViewSet Create. Data -> {json.dumps(data, indent=4)}")
            pkg_name: str = data.get(WebAppConstants.PACKAGE_NAME)
            pkg_version: str = data.get(WebAppConstants.PACKAGE_VERSION)
            pkg_cve: str = data.get(WebAppConstants.CVE)
            is_removal: bool = data.get(WebAppConstants.IS_REMOVAL)
            if pkg_version is None or pkg_name is None or pkg_cve is None:
                self.logger.error("Package name or Package version or CVE is null")
                return Response({GlobalConstants.ERROR_CAPS: "Package name or Package version or CVE is null"}, status=status.HTTP_400_BAD_REQUEST)
            if is_removal:
                result_or_false_positive = check_if_false_positive(pkg_name, pkg_version, pkg_cve)
                if result_or_false_positive:
                    result_or_false_positive.delete()
                self.logger.info(f"End FalsePositiveViewSet Create - Removal. Success")
                return Response(status=status.HTTP_200_OK)
            else:
                result_or_false_positive = check_if_false_positive(pkg_name, pkg_version, pkg_cve)
                if result_or_false_positive == None:
                    new_false_positive = FalsePositive()
                    new_false_positive.package_name = pkg_name
                    new_false_positive.package_version = pkg_version
                    new_false_positive.cve = pkg_cve
                    new_false_positive.save()
                self.logger.info(f"End FalsePositiveViewSet Create - Addition. Success")
                return Response(status=status.HTTP_200_OK)
        except Exception as ex:
            self.logger.error(f"Exception ({ex}) occured in FalsePositiveViewSet Create")
            self.logger.error(traceback.format_exc())
            return Response({GlobalConstants.ERROR_CAPS: ex}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ScanReportViewSet(viewsets.ModelViewSet):
    authentication_classes = [authentication.SessionAuthentication, authentication.BasicAuthentication]
    queryset = ScanReport.objects.all()
    serializer_class = ScanReportSerializer
    http_method_names = [GlobalConstants.GET, GlobalConstants.POST]
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    logger: Logger = Logger(WebAppConfig.LOG_FILE_PATH)

    def create(self, request, *args, **kwargs):
        data: Dict[str, Any] = request.data
        try:
            self.logger.info(f"Start ScanReportViewSet Create. Data -> {json.dumps(data, indent=4)}")
            new_scan_report = ScanReport()
            if ScanReportConstants.SCAN_SOFTWARE in data and data.get(ScanReportConstants.SCAN_SOFTWARE) == ScanReportConstants.BLACKDUCK:
                if ScanReportConstants.VERSION in data and ScanReport.objects.filter(version=data.get(ScanReportConstants.VERSION)).exists():
                    new_scan_report = get_scan_result_by_version(data.get(ScanReportConstants.VERSION))
                    self.logger.info(f"Record with Version: {data.get(ScanReportConstants.VERSION)} exists")
            new_scan_report.type: str = data.get(ScanReportConstants.TYPE)
            if new_scan_report.type not in WebAppConfig.POSSIBLE_SCAN_TYPES:
                self.logger.error(f"Type: {new_scan_report.type} not recognized")
                return Response({GlobalConstants.ERROR_CAPS: f"Type: {new_scan_report.type} not recognized"}, status=status.HTTP_400_BAD_REQUEST)
            new_scan_report.version: str = data.get(ScanReportConstants.VERSION)
            new_scan_report.user: str = data.get(ScanReportConstants.USER)
            new_scan_report.date: str = data.get(ScanReportConstants.DATE)
            new_scan_report.time: str = data.get(ScanReportConstants.TIME)
            new_scan_report.root_dir: str = data.get(ScanReportConstants.ROOT_DIR)
            new_scan_report.scan_software: str = data.get(ScanReportConstants.SCAN_SOFTWARE) if data.get(ScanReportConstants.SCAN_SOFTWARE) else ScanReportConstants.TWISTLOCK
            new_scan_report.ip_address_list: str = json.dumps(data.get(ScanReportConstants.IP_ADDRESS_LIST))
            new_scan_report.image_result_list: str = json.dumps(data.get(ScanReportConstants.REPORT_PATHS_LIST))
            new_scan_report.save()
            self.logger.info(f"Start ScanReportViewSet Create. Success -> {new_scan_report.id}")
            return Response({'id': new_scan_report.id}, status=status.HTTP_200_OK)
        except Exception as ex:
            self.logger.error(f"Exception ({ex}) occured in ScanReportViewSet Create")
            self.logger.error(traceback.format_exc())
            return Response({GlobalConstants.ERROR_CAPS: ex}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ReportDetailsViewSet(viewsets.GenericViewSet):
    authentication_classes = [authentication.SessionAuthentication, authentication.BasicAuthentication]
    queryset = ScanReport.objects.all()
    serializer_class = ScanReportSerializer
    http_method_names = [GlobalConstants.GET]
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    logger: Logger = Logger(WebAppConfig.LOG_FILE_PATH)

    @action(detail=False, methods=['GET'])
    def sort_by_package_name(self, request):
        try:
            self.logger.info(f"Start ReportDetailsViewSet sort_by_package_name. Data -> {json.dumps(request.GET, indent=4, default=str)}")
            scan_id: str = request.GET.get(WebAppConstants.SCAN_ID)
            image_id: int = int(request.GET.get(WebAppConstants.IMAGE_ID, "99999"))
            scan_result = get_scan_result_by_id(scan_id)
            if scan_result is None or image_id >= len(scan_result.image_result_list):
                self.logger.error(f"Scan ID: {scan_id} or Image Number: {image_id} not valid")
                return Response({GlobalConstants.ERROR_CAPS: f"Scan ID: {scan_id} or Image Number: {image_id} not valid"}, status=status.HTTP_400_BAD_REQUEST)
            report_result = DisplayResult(scan_id, image_id)
            report_result.expanded_cve_list.sort(key=lambda i: i.get(WebAppConstants.PACKAGE_NAME))
            report_result.expanded_false_positive_cve_list.sort(key=lambda i: i.get(WebAppConstants.PACKAGE_NAME))
            report_result.compliance_list.sort(key=lambda i:i['severity'])
            keys = list(report_result.collapsed_cve_dict.keys())
            report_result.collapsed_cve_dict = {i: report_result.collapsed_cve_dict[i] for i in keys}
            self.logger.info(f"End ReportDetailsViewSet sort_by_package_name {scan_result.image_result_list[0].image_name}")
            return Response(report_result.toJson(), status=status.HTTP_200_OK)
        except Exception as ex:
            self.logger.error(f"Exception ({ex}) occured in ReportDetailsViewSet sort_by_package_name")
            self.logger.error(traceback.format_exc())
            return Response({GlobalConstants.ERROR_CAPS: ex}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @action(detail=False, methods=['GET'])
    def sort_by_package_cvss(self, request):
        try:
            self.logger.info(f"Start ReportDetailsViewSet sort_by_package_cvss. Data -> {json.dumps(request.GET, indent=4, default=str)}")
            scan_id: str = request.GET.get(WebAppConstants.SCAN_ID)
            image_id: int = int(request.GET.get(WebAppConstants.IMAGE_ID, "99999"))
            scan_result = get_scan_result_by_id(scan_id)
            if scan_result is None or image_id >= len(scan_result.image_result_list):
                self.logger.error(f"Scan ID: {scan_id} or Image Number: {image_id} not valid")
                return Response({GlobalConstants.ERROR_CAPS: f"Scan ID: {scan_id} or Image Number: {image_id} not valid"}, status=status.HTTP_400_BAD_REQUEST)
            report_result = DisplayResult(scan_id, image_id)
            report_result.expanded_cve_list.sort(key=lambda i: i.get(WebAppConstants.PACKAGE_NAME))
            report_result.expanded_cve_list.sort(key=lambda i: i.get("cvss"), reverse=True)
            report_result.expanded_false_positive_cve_list.sort(key=lambda i: i.get(WebAppConstants.PACKAGE_NAME))
            report_result.expanded_false_positive_cve_list.sort(key=lambda i: i.get("cvss"))
            report_result.compliance_list.sort(key=lambda i:i['severity'])
            keys = list(report_result.collapsed_cve_dict.keys())
            report_result.collapsed_cve_dict = {i: report_result.collapsed_cve_dict[i] for i in keys}
            return Response(report_result.toJson(), status=status.HTTP_200_OK)
        except Exception as ex:
            self.logger.error(f"Exception ({ex}) occured in ReportDetailsViewSet sort_by_package_cvss")
            self.logger.error(traceback.format_exc())
            return Response({GlobalConstants.ERROR_CAPS: ex}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @action(detail=False, methods=['GET'])
    def get_versions_from_scan_type(self, request):
        try:
            scan_type: str = request.GET.get(ScanReportConstants.TYPE)
            if scan_type not in WebAppConfig.POSSIBLE_SCAN_TYPES:
                return Response({GlobalConstants.ERROR_CAPS: f"Type: {scan_type} not recognized"}, status=status.HTTP_400_BAD_REQUEST)
            versions = []
            scan_results = ScanReport.objects.filter(type=scan_type)
            names = []
            for scan_result in scan_results:
                versions.append(scan_result.version)
                names.append(scan_result.user)
            return_result = {
                ScanReportConstants.TYPE:scan_type,
            }
            if scan_type in BlackduckProjectConfig.PROJECT_NAME_ID_MAPPING.values():
                return_result["versions"] = versions
                return_result["names"] = names
            else:
                return_result["versions"] = sorted(set(versions), reverse=True)
            return Response(return_result, status=status.HTTP_200_OK)
        except Exception as ex:
            self.logger.error(f"Exception ({ex}) occured in ReportDetailsViewSet get_versions_from_scan_type")
            self.logger.error(traceback.format_exc())
            return Response({GlobalConstants.ERROR_CAPS: ex}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @action(detail=False, methods=['GET'])
    def get_date_time_user_from_version_and_scan_type(self, request):
        try:
            scan_type: str = request.GET.get(ScanReportConstants.TYPE)
            version: str = request.GET.get(WebAppConstants.VERSION)
            if scan_type not in WebAppConfig.POSSIBLE_SCAN_TYPES or version is None:
                return Response({GlobalConstants.ERROR_CAPS: f"Type: {scan_type} or version: {version} not recognized"}, status=status.HTTP_400_BAD_REQUEST)
            scan_results = ScanReport.objects.filter(type=scan_type,version=version)
            return_result: List[Dict[str, str]] = []
            for scan_result in scan_results:
                return_result.append({
                    ScanReportConstants.TYPE: scan_type,
                    WebAppConstants.VERSION: version,
                    ScanReportConstants.DATE: scan_result.date,
                    ScanReportConstants.TIME: scan_result.time,
                    ScanReportConstants.USER: scan_result.user,
                    ScanReportConstants.ID: scan_result.id
                })
            return_result.sort(key=lambda i: parse_common_time(i.get(ScanReportConstants.TIME)), reverse=True)
            return_result.sort(key=lambda i: parse_common_date(i.get(ScanReportConstants.DATE)), reverse=True)
            return Response(return_result, status=status.HTTP_200_OK)
        except Exception as ex:
            self.logger.error(f"Exception ({ex}) occured in ReportDetailsViewSet get_date_time_user_from_version_and_scan_type")
            self.logger.error(traceback.format_exc())
            return Response({GlobalConstants.ERROR_CAPS: ex}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @action(detail=False, methods=['GET'])
    def get_image_names_from_scan_id(self, request):
        try:
            scan_id: str = request.GET.get('id')
            scan_result = ScanReport.objects.filter(id=scan_id).first()
            if not scan_result:
                return Response({GlobalConstants.ERROR_CAPS: f"Scan ID: {scan_id} is not valid"}, status=status.HTTP_400_BAD_REQUEST)
            return_result: Dict[str, Any] = {
                'id': scan_id
            }
            images_dict: Dict[str, str] = {}
            i=0
            for image_result in scan_result.get_report_paths_list():
                images_dict[image_result.image_name] = i
                i = i+1
            keys = list(images_dict.keys())
            images_dict = {i: images_dict[i] for i in keys}
            return_result["images"] = images_dict
            return Response(return_result, status=status.HTTP_200_OK)
        except Exception as ex:
            self.logger.error(f"Exception ({ex}) occured in ReportDetailsViewSet get_image_names_from_scan_id")
            self.logger.error(traceback.format_exc())
            return Response({GlobalConstants.ERROR_CAPS: ex}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

    @action(detail=False, methods=['GET'])
    def compare_reports(self, request):
        try:
            scan_id_1: str = request.GET.get('id_first')
            scan_id_2: str = request.GET.get('id_second')
            image_id_1: int = int(request.GET.get('image_id_first',"999999"))
            image_id_2: int = int(request.GET.get('image_id_second', "999999"))
            scan_result_1 = get_scan_result_by_id(scan_id_1)
            scan_result_2 = get_scan_result_by_id(scan_id_2)
            if scan_result_1 is None or image_id_1 >= len(scan_result_1.image_result_list):
                return Response({GlobalConstants.ERROR_CAPS: f"First scan iD: {scan_id_1} or Image Number: {image_id_1} not valid"}, status=status.HTTP_400_BAD_REQUEST)
            if scan_result_2 is None or image_id_2 >= len(scan_result_2.image_result_list):
                return Response({GlobalConstants.ERROR_CAPS: f"First scan iD: {scan_id_2} or Image Number: {image_id_2} not valid"}, status=status.HTTP_400_BAD_REQUEST)
            report_result_1 = DisplayResult(scan_id_1, image_id_1)
            report_result_1.expanded_cve_list.sort(key=lambda i: i.get(WebAppConstants.CVE))
            report_result_2 = DisplayResult(scan_id_2, image_id_2)
            report_result_2.expanded_cve_list.sort(key=lambda i: i.get(WebAppConstants.CVE))
            scan_result_1_expanded_cve_list: List[Dict[str, str]] = []
            scan_result_2_expanded_cve_list: List[Dict[str, str]] = []
            common_expanded_cve_list: List[Dict[str, str]] = []
            common_expanded_false_positive_list: List[Dict[str, str]] = []
            l=0
            r=0
            while(l<len(report_result_1.expanded_cve_list) and r<len(report_result_2.expanded_cve_list)):
                if report_result_1.expanded_cve_list[l].get(WebAppConstants.CVE) == report_result_2.expanded_cve_list[r].get(WebAppConstants.CVE) and report_result_1.expanded_cve_list[l].get(WebAppConstants.PACKAGE_NAME) == report_result_2.expanded_cve_list[r].get(WebAppConstants.PACKAGE_NAME):
                    common_expanded_cve_list.append(report_result_1.expanded_cve_list[l])
                    l = l+1
                    r = r+1
                elif report_result_1.expanded_cve_list[l].get(WebAppConstants.CVE) == report_result_2.expanded_cve_list[r].get(WebAppConstants.CVE):
                    scan_result_1_expanded_cve_list.append(report_result_1.expanded_cve_list[l])
                    scan_result_2_expanded_cve_list.append(report_result_2.expanded_cve_list[r])
                    l = l+1
                    r = r+1
                elif report_result_1.expanded_cve_list[l].get(WebAppConstants.CVE) < report_result_2.expanded_cve_list[r].get(WebAppConstants.CVE):
                    scan_result_1_expanded_cve_list.append(report_result_1.expanded_cve_list[l])
                    l = l+1
                else:
                    scan_result_2_expanded_cve_list.append(report_result_2.expanded_cve_list[r])
                    r = r+1
            while(l<len(report_result_1.expanded_cve_list)):
                scan_result_1_expanded_cve_list.append(report_result_1.expanded_cve_list[l])
                l = l+1
            while(r<len(report_result_2.expanded_cve_list)):
                scan_result_2_expanded_cve_list.append(report_result_2.expanded_cve_list[r])
                r = r +1
            false_positive_dict: Dict[str, int] = {}
    
            for item in report_result_1.expanded_false_positive_cve_list:
                false_positive_dict[f"{item.get(WebAppConstants.PACKAGE_NAME)}{item.get(WebAppConstants.VERSION)}{item.get(WebAppConstants.CVE)}"] = 0
                common_expanded_false_positive_list.append(item)
            for item in report_result_2.expanded_false_positive_cve_list:
                if f"{item.get(WebAppConstants.PACKAGE_NAME)}{item.get(WebAppConstants.VERSION)}{item.get(WebAppConstants.CVE)}" not in false_positive_dict:
                    common_expanded_false_positive_list.append(item)
            scan_result_1_expanded_cve_list.sort(key=lambda i: i.get(WebAppConstants.PACKAGE_NAME))
            scan_result_2_expanded_cve_list.sort(key=lambda i: i.get(WebAppConstants.PACKAGE_NAME))
            common_expanded_cve_list.sort(key=lambda i: i.get(WebAppConstants.PACKAGE_NAME))
            common_expanded_false_positive_list.sort(key=lambda i: i.get(WebAppConstants.PACKAGE_NAME))
            to_return = {
                "scan_result_first": scan_result_1_expanded_cve_list,
                "scan_result_second": scan_result_2_expanded_cve_list,
                "common_scan_result": common_expanded_cve_list,
                "all_false_positive": common_expanded_false_positive_list
            }
            return Response(to_return, status=status.HTTP_200_OK)
        except Exception as ex:
            self.logger.error(f"Exception ({ex}) occured in ReportDetailsViewSet compare_reports")
            self.logger.error(traceback.format_exc())
            return Response({GlobalConstants.ERROR_CAPS: ex}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

##########################
###### Page Renderers ######
##########################

def home(request):
    twistlock_scans: Dict[str, List[ScanReport]] = {}
    twistlock_scans_length: Dict[str, int] = {}
    bduck_scans: Dict[str, List[ScanReport]] = {}
    bduck_scans_length: Dict[str, int] = {}
    for scan_type in TwistlockProjectConfig.PROJECT_TYPES:
        twistlock_scans[scan_type] = get_all_scans_collected_by_type(scan_type)[:5]
        twistlock_scans_length[scan_type] = len(twistlock_scans[scan_type])
    for scan_type in BlackduckProjectConfig.PROJECT_NAME_ID_MAPPING.values():
        bduck_scans[scan_type] = get_all_scans_collected_by_type(scan_type)[:5]
        bduck_scans_length[scan_type] = len(bduck_scans[scan_type])
    context = {
        "twistlock_scans": twistlock_scans,
        "twistlock_scans_length": twistlock_scans_length,
        "bduck_scans": bduck_scans,
        "bduck_scans_length": bduck_scans_length,

    }
    return render(request, 'home.html', context)


def login_user(request):
    if request.method == 'POST':
        user = authenticate(request, username=request.POST['username'], password=request.POST['password'])
        if user:
            login(request, user)
            return redirect('home')
        else:
            messages.error(request, "Invalid Creds!")
            return redirect('login')
    else:
        return render(request, 'login.html', {
            WebAppConstants.PAGE_NAME: 'Log In'
        })


def logout_user(request):
    logout(request)
    return redirect('home')


def page_not_found(request):
    return render(request, 'page_not_found.html', {WebAppConstants.PAGE_NAME: "Whoops... Looks Like We Lost One!"})


def all_scans(request):
    scan_type: str = request.GET.get('scan_type')
    all_scans = List[ScanReport]
    if scan_type not in WebAppConfig.POSSIBLE_SCAN_TYPES:
        return redirect('page-not-found')
    all_scans = get_all_scans_collected_by_type(scan_type)
    page_name: str = f"All {scan_type.capitalize()} Scans"
    if scan_type in BlackduckProjectConfig.PROJECT_NAME_ID_MAPPING.values():
        page_name = f"All {BlackduckProjectConfig.PROJECT_ID_NAME_MAPPING[scan_type]} Scans"
    context = {
        WebAppConfig.PAGE_NAME: page_name,
        'all_scans': all_scans
    }
    return render(request, 'all_scans.html', context)


def scan_details(request):
    scan_id: str = request.GET.get(WebAppConstants.SCAN_ID)
    scan_result = get_scan_result_by_id(scan_id)
    if scan_result is None:
        return redirect('page-not-found')
    type: str = scan_result.type
    version: str = scan_result.version
    if scan_result.type in BlackduckProjectConfig.PROJECT_NAME_ID_MAPPING.values():
        type = f"{BlackduckProjectConfig.PROJECT_ID_NAME_MAPPING[scan_result.type]}"
        version = scan_result.user
    context = {
        WebAppConstants.PAGE_NAME: f"{type} | {version} | {scan_result.date}",
        'scan_result': scan_result,
        'i':0
    }
    return render(request, 'scan_details.html', context)
        
def report_details(request):
    scan_id: str = request.GET.get(WebAppConstants.SCAN_ID)
    image_id: int = int(request.GET.get(WebAppConstants.IMAGE_ID, "99999"))
    if type_filter is None:
        type_filter = "Default"
    if image_filter is None:
        image_filter = "Default"
    scan_result = get_scan_result_by_id(scan_id)
    if scan_result is None or image_id >= len(scan_result.image_result_list):
        return redirect('page-not-found')
    context = {
        WebAppConstants.PAGE_NAME: f"{scan_result.image_result_list[image_id].image_name}",
        WebAppConstants.SCAN_ID: scan_id,
        WebAppConstants.IMAGE_ID: image_id
    }
    return render(request, 'report_details.html', context)

def download_file(request):
    logger: Logger = Logger(WebAppConfig.LOG_FILE_PATH)
    logger.info(f"Start download file. Data -> {json.dumps(request.GET, indent=4, default=str)}")
    file_type: str = request.GET.get('file_type')
    scan_id: str = request.GET.get(WebAppConstants.SCAN_ID)
    image_id: int = int(request.GET.get(WebAppConstants.IMAGE_ID, "99999"))
    scan_result = get_scan_result_by_id(scan_id)
    if scan_result is None or image_id >= len(scan_result.image_result_list) or file_type not in ["pdf", "ujson", "pjson"]:
        return HttpResponse('File not found', status=404)
    image_result = scan_result.image_result_list[image_id]
    if file_type == "pdf":
        pdf_client = PdfReport(WebAppConfig.LOG_FILE_PATH)
        pdf_client.save_pdf(scan_id, image_id, image_result.formatted_report_path)
    file_path: str
    content_type='application/json'
    if file_type == "pdf":
        file_path = image_result.formatted_report_path
        content_type='application/pdf'
    if file_type == "pjson":
        file_path = image_result.processed_report_path
    if file_type == "ujson" and scan_result.type == TwistlockProjectConfig.KUBERNETES_TWISTLOCK:
        return HttpResponse('File not found', status=404)
    if file_type == "ujson":
        file_path = image_result.raw_report_path
    if os.path.exists(file_path):
        response = FileResponse(open(file_path, 'rb'), content_type=content_type)
        response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
        return response
    else:
        return HttpResponse('File not found', status=404)

def compare_reports(request):
    scan_id: str = request.GET.get(WebAppConstants.SCAN_ID)
    image_id: int = int(request.GET.get(WebAppConstants.IMAGE_ID, "99999"))
    scan_type: str = None
    scan_result = get_scan_result_by_id(scan_id)
    if scan_result is None or image_id >= len(scan_result.image_result_list):
        scan_id = None
        image_id = None
    else:
        scan_type = scan_result.type
    context = {
        WebAppConstants.PAGE_NAME: "Report Comparison",
        "id_first": scan_id,
        "image_id_first": image_id,
        "type": scan_type
    }
    return render(request, 'compare_reports.html', context)