from .core.constants import CveConstants, ProcessedReportConstants, WebAppConstants
from .core.helpers.datetimeconverter import format_common_date, format_common_time
from .models import Cve, FalsePositive, ScanReport
from datetime import datetime
from typing import Dict, List, Optional, Any

import json

def check_if_false_positive(pkg_name, pkg_version, cve) -> Optional[FalsePositive]:
    for cve_row in FalsePositive.objects.all():
        if cve_row.package_name == pkg_name and cve_row.package_version == pkg_version and cve_row.cve == cve:
            return cve_row
    return None

def get_jiras_from_cve(cve_id: str) -> List[List[str]]:
    try:
        if cve_id is None or cve_id == "":
            return []
        cve = Cve.objects.get(cve_id=cve_id)
        return cve.get_jira_list()
    except Cve.DoesNotExist:
        return []

def get_all_scans_collected_by_type(scan_type: str) -> List[ScanReport]:
    to_return = list(ScanReport.objects.filter(type=scan_type))
    to_return.sort(key=lambda i: i.get_time(), reverse=True)
    to_return.sort(key=lambda i: i.get_date(), reverse=True)
    i = 0
    while(i < len(to_return)):
        to_return[i].image_result_list = to_return[i].get_report_paths_list()
        to_return[i].image_result_list.sort(key=lambda i: i.image_name)
        to_return[i].ip_address_list = to_return[i].get_ip_address_list()
        i += 1
    return to_return

def get_scan_result_by_id(scan_id: str) -> Optional[ScanReport]:
    scan_result = ScanReport.objects.filter(id=scan_id).first()
    if scan_result:
        scan_result.image_result_list = scan_result.get_report_paths_list()
        scan_result.image_result_list.sort(key=lambda i: i.image_name)
        scan_result.ip_address_list = scan_result.get_ip_address_list()
    return scan_result

def get_scan_result_by_version(version: str) -> Optional[ScanReport]:
    scan_result = ScanReport.objects.filter(version=version).first()
    if scan_result:
        scan_result.image_result_list = scan_result.get_report_paths_list()
        scan_result.image_result_list.sort(key=lambda i: i.image_name)
        scan_result.ip_address_list = scan_result.get_ip_address_list()
    return scan_result

class DisplayResult:

    def __init__(self, scan_id: str, image_no: int) -> None:
        scan_result = get_scan_result_by_id(scan_id)
        report_result = scan_result.image_result_list[image_no]
        processed_file_path = report_result.processed_report_path
        report_json = Dict[str, Any]
        with open(processed_file_path, "r") as fl:
            report_json = json.load(fl)
        self.id: str = scan_id
        self.image_id: int = image_no
        self.scan_type: str = scan_result.type
        self.date: datetime =scan_result.get_date()
        self.time: datetime = scan_result.get_time()
        self.version: str = scan_result.version
        self.image_name: str = report_json.get(ProcessedReportConstants.NAME, "")
        self.distro: str = report_json.get(ProcessedReportConstants.DISTRO, "")
        self.distro_release: str = report_json.get(ProcessedReportConstants.DISTRORELEASE, "")
        self.namespaces: str = report_json.get(ProcessedReportConstants.NAMESPACES, "")
        self.secrets: str = report_json.get(ProcessedReportConstants.SECRETS, "")

        self.expanded_cve_list: List[Dict[str, str]] = []
        self.expanded_false_positive_cve_list: List[Dict[str, str]] = []
        self.collapsed_cve_dict: Dict[str, Any] = {}
        self.compliance_list: List[Dict[str, str]] = report_json.get(ProcessedReportConstants.COMPLIANCE_RESULTS, [])
        for package_name in report_json.get(ProcessedReportConstants.CVE_RESULTS, {}):
            for version in report_json[ProcessedReportConstants.CVE_RESULTS].get(package_name,{}):
                paths = report_json[ProcessedReportConstants.CVE_RESULTS][package_name][version].get(ProcessedReportConstants.PATH,[])
                for cve, cve_result in report_json[ProcessedReportConstants.CVE_RESULTS][package_name][version].get(ProcessedReportConstants.CVES,{}).items():
                    cve_json = {
                        WebAppConstants.PACKAGE_NAME: package_name.lower() if package_name else "",
                        WebAppConstants.VERSION: version,
                        WebAppConstants.CVE: cve,
                        CveConstants.CVSS: cve_result.get(CveConstants.CVSS),
                        CveConstants.STATUS: cve_result.get(CveConstants.STATUS),
                        CveConstants.VENDOR_LINK_KEY: cve_result.get(CveConstants.VENDOR_LINK_KEY),
                        CveConstants.NVD_LINK_KEY: cve_result.get(CveConstants.NVD_LINK_KEY),
                        WebAppConstants.JIRA_LIST: [],
                        WebAppConstants.PATH_LIST: paths
                    }
                    for jiraa in get_jiras_from_cve(cve.upper()):
                        jira_id: str = jiraa[0]
                        status: str = jiraa[1] if (len(jiraa) >=2 and jiraa[1] != "") else None
                        summary: str = jiraa[2] if len(jiraa) >=3 else ""        
                        if status:
                            cve_json[WebAppConstants.JIRA_LIST].append({
                                "jira": jira_id,
                                "status": status
                            })
                    if check_if_false_positive(package_name, version, cve):
                        self.expanded_false_positive_cve_list.append(cve_json)
                    else:
                        self.expanded_cve_list.append(cve_json)
        for cve_json in self.expanded_cve_list:
            if cve_json[WebAppConstants.PACKAGE_NAME] not in self.collapsed_cve_dict:
                self.collapsed_cve_dict[cve_json[WebAppConstants.PACKAGE_NAME]] = {
                    "version_list": [],
                    "path_list": [],
                    "cve_list":[],
                    WebAppConstants.JIRA_LIST:[]
                }
            self.collapsed_cve_dict[cve_json[WebAppConstants.PACKAGE_NAME]].get('version_list').append(cve_json[WebAppConstants.VERSION])
            [self.collapsed_cve_dict[cve_json[WebAppConstants.PACKAGE_NAME]].get('path_list').append(path) for path in cve_json['path_list']]
            if cve_json[WebAppConstants.CVE] not in [item[0] for item in self.collapsed_cve_dict[cve_json[WebAppConstants.PACKAGE_NAME]].get('cve_list')]:
                self.collapsed_cve_dict[cve_json[WebAppConstants.PACKAGE_NAME]].get('cve_list').append([cve_json[WebAppConstants.CVE], cve_json["cvss"], cve_json["link"]])
            for jira in cve_json[WebAppConstants.JIRA_LIST]:
                if jira["jira"] not in [item[0] for item in self.collapsed_cve_dict[cve_json[WebAppConstants.PACKAGE_NAME]].get(WebAppConstants.JIRA_LIST)]:
                    self.collapsed_cve_dict[cve_json[WebAppConstants.PACKAGE_NAME]].get(WebAppConstants.JIRA_LIST).append([jira["jira"], jira["status"]])
            self.collapsed_cve_dict[cve_json[WebAppConstants.PACKAGE_NAME]]["version_list"] = list(set(self.collapsed_cve_dict[cve_json[WebAppConstants.PACKAGE_NAME]].get('version_list')))
            self.collapsed_cve_dict[cve_json[WebAppConstants.PACKAGE_NAME]]["path_list"] = list(set(self.collapsed_cve_dict[cve_json[WebAppConstants.PACKAGE_NAME]].get('path_list')))
    
    def toJson(self):
        return {
            "Id": self.id,
            "ImageId": self.image_id,
            "ImageName": self.image_name,
            "Date": format_common_date(self.date),
            "Type": self.scan_type,
            "Time": format_common_time(self.time),
            "Version": self.version,
            "Distro": self.distro,
            "DistroRelease": self.distro_release,
            "Namespaces": self.namespaces,
            "Secrets": self.secrets,
            "ExpandedCveList": self.expanded_cve_list,
            "ExpandedFalseCveList": self.expanded_false_positive_cve_list,
            "CollapsedCveDict":self.collapsed_cve_dict,
            "ComplianceList":self.compliance_list
        }