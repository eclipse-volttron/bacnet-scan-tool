from sqlmodel import SQLModel, Field
from typing import Optional, List, Any, Dict, Union
from pydantic import BaseModel, field_validator


class IPAddress(BaseModel):
    address: str


class LocalIPResponse(BaseModel):
    local_ip: str
    subnet_mask: Optional[str] = None
    cidr: Optional[str] = None
    error: Optional[str] = None


class ProxyResponse(BaseModel):
    status: str
    address: Optional[str] = None
    message: Optional[str] = None
    error: Optional[str] = None


# Used for scan responses
class BACnetDevice(BaseModel):
    device_instance: int
    deviceIdentifier: str
    address: Optional[str] = None
    maxAPDULengthAccepted: Optional[int] = None
    segmentationSupported: Optional[str] = None
    vendorID: Optional[int] = None


class ScanResponse(BaseModel):
    status: str
    devices: Optional[List[BACnetDevice]] = None
    error: Optional[str] = None
    message: Optional[str] = None
    ips_scanned: int


class PropertyReadResponse(BaseModel):
    status: str
    result: Optional[Any] = None
    error: Optional[str] = None


class DevicePropertiesResponse(BaseModel):
    status: str
    properties: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class WhoIsResponse(BaseModel):
    status: str
    devices: Optional[List[Dict[str, Any]]] = None
    error: Optional[str] = None


class PingResponse(BaseModel):
    ip_address: str
    success: bool
    output: Optional[str] = None
    error: Optional[str] = None


class PaginationInfo(BaseModel):
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class ObjectProperties(BaseModel):
    object_name: str
    units: Optional[str] = None
    present_value: Optional[str] = None


class ObjectListNamesResponse(BaseModel):
    status: str
    results: Optional[Dict[str, ObjectProperties]] = None
    pagination: Optional[PaginationInfo] = None
    error: Optional[str] = None


class SavedDevice(BaseModel):
    device_instance: str
    device_address: str
    vendor_id: str
    first_discovered: str
    last_seen: str
    scan_count: str
    networks_found_on: str


class SavedScansResponse(BaseModel):
    status: str
    devices: List[SavedDevice]
    total_count: int
    error: Optional[str] = None


class ScannedPoint(BaseModel):
    device_address: str
    device_object_identifier: str
    object_id: str
    object_name: str
    units: str
    present_value: str
    object_type: str
    first_discovered: str
    last_updated: str
    read_count: str


class ScannedPointsResponse(BaseModel):
    status: str
    points: List[ScannedPoint]
    total_count: int
    filtered_by: Optional[str] = None
    error: Optional[str] = None
