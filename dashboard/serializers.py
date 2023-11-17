from .models import Cve, FalsePositive, ScanReport
from rest_framework import serializers


class CveSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Cve
        fields = ('cve_id', 'jiras')

class FalsePositiveSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = FalsePositive
        fields = ('id', 'package_name', 'package_version', 'cve')

class ScanReportSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = ScanReport
        fields = ('id', 'type', 'version', 'user', 'date', 'time', 'root_dir', 'ip_address_list', 'image_result_list', 'scan_software')