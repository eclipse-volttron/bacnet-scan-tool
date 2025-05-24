import asyncio
import json

from fastapi import FastAPI, HTTPException, Depends
from sqlmodel import SQLModel, Session, create_engine, select

from src.protocol_proxy.bacnet_proxy import BACnetProxy
from src.protocol_proxy.ipc import ProtocolProxyMessage
from src.protocol_proxy.manager import ProtocolProxyManager
from . models import Device, Point, Tag, CreateTagRequest, WritePointValueRequest



# TODO handle who is AND just one device.
app = FastAPI()

# SQLite database setup
DATABASE_URL = "sqlite:///./bacnet.db"
engine = create_engine(DATABASE_URL)

@app.on_event("startup")
async def on_startup():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session

@app.get("/query_device")
async def query_device(address: str, property_name: str):

    ppm = ProtocolProxyManager.get_manager(BACnetProxy)

    message = ProtocolProxyMessage(
        method_name="QUERY_DEVICE",
        payload=json.dumps({
        "address": address,
        "object_identifier": 'device:4194303',
        "property_name": property_name
    }).encode('utf8'))

    remote_params = ppm.peers.socket_params
    send_result = ppm.send(remote_params, message)
    print("Sent READ_PROPERTY message")
    return send_result

@app.get("/read_property")
async def read_property(device_address: str, object_identifier: str, property_identifier: str,
                               property_array_index: int = None):

    ppm = ProtocolProxyManager.get_manager(BACnetProxy)

    message = ProtocolProxyMessage(
        method_name="READ_PROPERTY",
        payload=json.dumps({
        "device_address": device_address,
        "object_identifier": object_identifier,
        "property_identifier": property_identifier,
        "property_array_index": property_array_index
    }).encode('utf8'))

    remote_params = ppm.peers.socket_params
    send_result = ppm.send(remote_params, message)
    print("Sent READ_PROPERTY message")

    return send_result

@app.post("/write_property")
async def write_property(device_address: str, object_identifier: str, property_identifier: str, value: any,
                         priority: int, property_array_index: int = None):
    """
    Write a value to a specific property of a device point.
    """
    ppm = ProtocolProxyManager.get_manager(BACnetProxy)
    message = ProtocolProxyMessage(
        method_name="WRITE_PROPERTY",
        payload=json.dumps({
            "device_address": device_address,
            "object_identifier": object_identifier,
            "property_identifier": property_identifier,
            "value": value,
            "priority": priority,
            "property_array_index": property_array_index
        }).encode('utf8')
    )

    remote_params = ppm.peers.socket_params
    send_result = ppm.send(remote_params, message)
    print("Sent WRITE_PROPERTY message")

    return send_result

#TODO what does "start" actuall mean, how will this work and what is the intended logic of this?
@app.get("/{tool}/scan/start")
async def start_bacnet_discovery(tool: str, ip_address: str, session: Session = Depends(get_session)):
    if tool != "bacnet":
        raise HTTPException(status_code=400, detail="Unsupported tool")
    device = Device(ip_address=ip_address)
    session.add(device)
    session.commit()
    session.refresh(device)
    return {"message": f"Discovery started for IP range: {ip_address}", "device_id": device.id}

@app.get("/devices")
async def get_devices(session: Session = Depends(get_session)):
    devices = session.exec(select(Device)).all()
    return {"devices": devices}

@app.get("/devices/{device_id}/points")
async def get_device_points(device_id: int, session: Session = Depends(get_session)):
    points = session.exec(select(Point).where(Point.device_id == device_id)).all()
    if not points:
        raise HTTPException(status_code=404, detail="Device not found")
    return {"points": points}

@app.get("/devices/{device_id}/points/values")
async def get_point_values(device_id: int):
    if device_id not in device_points:
        raise HTTPException(status_code=404, detail="Device not found")
    # Simulate retrieving updated values
    return {"values": {point_id: "value" for point_id in device_points[device_id]}}

@app.get("/devices/{device_id}/points/meta")
async def get_point_metadata(device_id: int):
    if device_id not in device_points:
        raise HTTPException(status_code=404, detail="Device not found")
    # Simulate metadata retrieval
    return {"metadata": {point_id: {"tag": "example", "unit": "unit"} for point_id in device_points[device_id]}}

@app.post("/devices/{device_id}/points/{point_id}/tags")
async def create_point_tag(device_id: int, point_id: int, request: CreateTagRequest, session: Session = Depends(get_session)):
    point = session.get(Point, point_id)
    if not point or point.device_id != device_id:
        raise HTTPException(status_code=404, detail="Device or point not found")
    tag = Tag(point_id=point_id, name=request.name)
    session.add(tag)
    session.commit()
    session.refresh(tag)
    return {"message": f"Tag '{request.name}' added to point {point_id} of device {device_id}", "tag_id": tag.id}

@app.get("/devices/{device_id}/points/{point_id}/tags")
async def get_point_tags(device_id: int, point_id: int):
    if device_id not in point_tags or point_id not in point_tags[device_id]:
        raise HTTPException(status_code=404, detail="Device or point not found")
    return {"tags": point_tags[device_id][point_id]}

@app.put("/devices/{device_id}/points/{point_id}/write")
async def write_point_value(device_id: int, point_id: int, request: WritePointValueRequest, session: Session = Depends(get_session)):
    point = session.get(Point, point_id)
    if not point or point.device_id != device_id:
        raise HTTPException(status_code=404, detail="Device or point not found")
    # Simulate writing a value
    return {"message": f"Value '{request.value}' written to point {point_id} of device {device_id}"}
