from .core.constants import ScanReportConstants
from .core.helpers.datetimeconverter import format_common_date, format_common_time, parse_common_date, parse_common_time
from .core.report import ReportPaths
from datetime import datetime
from django.db import models
from typing import Dict, List, Any

import json
import uuid

class FalsePositive(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    package_name = models.CharField(max_length=100)
    package_version = models.CharField(max_length=100)
    cve = models.CharField(max_length=30)

    def __str__(self) -> str:
        return f"{self.package_name}:::{self.package_version}:::{self.cve}"


class Cve(models.Model):
    cve_id = models.CharField(max_length=25, primary_key=True, editable=False)
    jiras = models.TextField(default='[]')

    def save(self, *args, **kwargs):
        # Ensure that the string_list field contains a valid JSON list before saving
        try:
            json.loads(self.jiras)
        except (TypeError, ValueError):
            raise ValueError("jiras must be a valid JSON list")
        super().save(*args, **kwargs)
    
    def get_jira_list(self) -> List[List[str]]:
        return json.loads(self.jiras)
    
    def add_jira_list(self, jira_id: str, jira_status: str = None, jira_summary: str = None) -> 'Cve':
        jiras = self.get_jira_list()
        i = 0
        already_present = False
        while(i<len(jiras)):
            if jiras[i][0] == jira_id.upper():
                if len(jiras[i]) >= 2:
                    jiras[i][1] = jira_status if jira_status else ""
                else:
                    jiras[i].append(jira_status if jira_status else "")
                if len(jiras[i]) >= 3:
                    jiras[i][2] = jira_summary if jira_summary else ""
                else:
                    jiras[i].append(jira_summary if jira_summary else "")
                already_present = True
                break
            i = i + 1
        if not already_present:
            jiras.append([jira_id.upper(), jira_status if jira_status else "", jira_summary if jira_summary else ""])
        self.jiras = json.dumps(jiras)
        return self
    
    def __str__(self) -> str:
        return f"{self.cve_id}:::{self.jiras}"


class ScanReport(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    type = models.CharField(max_length=300)
    version = models.CharField(max_length=300)
    user = models.CharField(max_length=300)
    date = models.CharField(max_length=300)
    time = models.CharField(max_length=300)
    root_dir = models.CharField(max_length=300, null=True)
    ip_address_list = models.TextField(default='[]')
    image_result_list = models.TextField(default='[]')
    scan_software = models.TextField(default=ScanReportConstants.TWISTLOCK)

    def get_date(self) -> datetime:
        return parse_common_date(self.date)
    
    def get_time(self) -> datetime:
        return parse_common_time(self.time)
    
    def get_ip_address_list(self) -> List[str]:
        return json.loads(self.ip_address_list)
    
    def add_ip_address(self, ip_address: str) -> 'ScanReport':
        temp_ip_address_list = self.get_ip_address_list()
        temp_ip_address_list.append(ip_address)
        self.ip_address_list = json.dumps(list(set(temp_ip_address_list)))
        return self
    
    def get_report_paths_list(self) -> List[ReportPaths]:
        image_results_json: List[Dict[str, str]] = json.loads(self.image_result_list)
        to_return: List[ReportPaths] = []
        for item in image_results_json:
            to_return.append(ReportPaths().fromJson(item))
        return to_return
    
    def add_image_result(self, image_result: ReportPaths) -> 'ScanReport':
        temp_image_result_list = self.get_report_paths_list()
        if image_result.image_name not in [image_result_item.image_name for image_result_item in temp_image_result_list]:
            temp_image_result_list.append(image_result)
        self.image_result_list = json.dumps([image_result_item.toJson() for image_result_item in temp_image_result_list])
        return self
    
    def toJson(self) -> Dict[str, Any]:
        to_return = {
            ScanReportConstants.TYPE: self.type,
            ScanReportConstants.VERSION: self.version,
            ScanReportConstants.USER: self.user,
            ScanReportConstants.ROOT_DIR: self.root_dir,
            ScanReportConstants.IP_ADDRESS_LIST: self.get_ip_address_list(),
            ScanReportConstants.REPORT_PATHS_LIST: [image_result.toJson() for image_result in self.get_report_paths_list()]
        }
        if type(self.date) is str:
            to_return[ScanReportConstants.DATE] = self.date
        else:
            to_return[ScanReportConstants.DATE] = format_common_date(self.date)
        if type(self.time) is str:
            to_return[ScanReportConstants.TIME] = self.time
        else:
            to_return[ScanReportConstants.TIME] = format_common_time(self.time)
        return to_return
    
    def fromJsonString(self, json_repr: Dict[str, str]) -> 'ScanReport':
        self.id = json_repr.get(ScanReportConstants.ID)
        self.type = json_repr.get(ScanReportConstants.TYPE)
        self.version = json_repr.get(ScanReportConstants.VERSION)
        self.user = json_repr.get(ScanReportConstants.USER)
        self.date: datetime = parse_common_date(json_repr.get(ScanReportConstants.DATE))
        self.time: datetime = parse_common_time(json_repr.get(ScanReportConstants.TIME))
        self.root_dir = json_repr.get(ScanReportConstants.ROOT_DIR)
        self.ip_address_list = json_repr.get(ScanReportConstants.IP_ADDRESS_LIST)
        self.image_result_list = json_repr.get(ScanReportConstants.REPORT_PATHS_LIST)
        self.scan_software = json_repr.get(ScanReportConstants.SCAN_SOFTWARE) if json_repr.get(ScanReportConstants.SCAN_SOFTWARE) else ScanReportConstants.TWISTLOCK
        return self