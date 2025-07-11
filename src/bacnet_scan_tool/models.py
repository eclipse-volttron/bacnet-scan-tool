from sqlmodel import SQLModel, Field
from typing import Optional, List, Any, Dict
from pydantic import BaseModel

class Device(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    ip_address: str

class Point(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    device_id: int
    name: str

class Tag(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    point_id: int
    name: str

# Pydantic request models
class CreateTagRequest(BaseModel):
    name: str

class WritePointValueRequest(BaseModel):
    value: str

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
    object_name: Optional[str] = None
    address: Optional[str] = None
    maxAPDULengthAccepted: Optional[int] = None
    segmentationSupported: Optional[str] = None
    vendorID: Optional[int] = None

class ScanResponse(BaseModel):
    status: str
    devices: Optional[List[BACnetDevice]] = None
    error: Optional[str] = None

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
