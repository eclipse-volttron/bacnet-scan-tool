from sqlmodel import SQLModel, Field
from typing import Optional, List, Any, Dict
from pydantic import BaseModel

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

class ObjectListNamesResponse(BaseModel):
    status: str
    results: Optional[Dict[str, str]] = None  # object_identifier -> object_name mapping
    pagination: Optional[PaginationInfo] = None
    error: Optional[str] = None
