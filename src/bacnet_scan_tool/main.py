import asyncio
import json
import uuid
from typing import Optional, Any

from fastapi import FastAPI, HTTPException, Depends, Form, Query, Body
from sqlmodel import SQLModel, Session, create_engine, select

from protocol_proxy.bacnet_proxy import BACnetProxy
from protocol_proxy.ipc import ProtocolProxyMessage
from protocol_proxy.manager import ProtocolProxyManager
from . models import Device, Point, Tag, CreateTagRequest, WritePointValueRequest



# TODO handle who is AND just one device.
app = FastAPI()

# SQLite database setup
DATABASE_URL = "sqlite:///./bacnet.db"
engine = create_engine(DATABASE_URL)

BACNET_PROXY_LOCAL_ADDRESS = "172.18.229.191"

@app.on_event("startup")
async def on_startup():
    SQLModel.metadata.create_all(engine)
    from protocol_proxy.bacnet_manager import AsyncioBACnetManager
    app.state.bacnet_manager = AsyncioBACnetManager(BACNET_PROXY_LOCAL_ADDRESS)
    app.state.bacnet_manager_task = asyncio.create_task(app.state.bacnet_manager.run())
    await asyncio.sleep(3)  # Give proxy time to start and register

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
    send_result = await ppm.send(remote_params, message)
    print("Sent READ_PROPERTY message")
    return send_result



@app.post("/write_property")
async def write_property(device_address: str, object_identifier: str, property_identifier: str, value: Any,
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
    send_result = await ppm.send(remote_params, message)
    print("Sent WRITE_PROPERTY message")

    return send_result

#TODO what does "start" actually mean, how will this work and what is the intended logic of this?
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

@app.post("/read_property")
async def read_property(
    device_address: str = Form(...),
    object_identifier: str = Form(...),
    property_identifier: str = Form(...),
    property_array_index: Optional[int] = Form(None)
):
    """
    Perform a BACnet property read and return the result directly (waits for completion).
    """
    from protocol_proxy.ipc import ProtocolProxyMessage
    import json
    print("[read_property] Using global AsyncioBACnetManager from app.state...")
    try:
        manager = app.state.bacnet_manager
        # Wait for proxy registration
        proxy_id = manager.ppm.get_proxy_id((BACNET_PROXY_LOCAL_ADDRESS, 0))
        peer = manager.ppm.peers.get(proxy_id)
        if not peer or not peer.socket_params:
            print("[read_property] Proxy not registered or missing socket_params!")
            return {"status": "error", "error": "Proxy not registered or missing socket_params, cannot send request."}

        payload = {
            'device_address': device_address,
            'object_identifier': object_identifier,
            'property_identifier': property_identifier
        }
        if property_array_index is not None:
            payload['property_array_index'] = property_array_index
        print(f"[read_property] Sending ProtocolProxyMessage: {payload}")

        result = await manager.ppm.send(peer.socket_params, ProtocolProxyMessage(
            method_name='READ_PROPERTY',
            payload=json.dumps(payload).encode('utf8'),
            response_expected=True
        ))
        print("[read_property] Got result from send()")
        if asyncio.isfuture(result):
            print("[read_property] Result is a Future, awaiting...")
            result = await result
        print(f"[read_property] Raw result: {result}")
        try:
            value = json.loads(result.decode('utf8'))
            print(f"[read_property] Decoded value: {value}")
            return {"status": "done", "result": value}
        except Exception as e:
            print(f"[read_property] Error decoding BACnet response: {e}")
            return {"status": "error", "error": f"Error decoding BACnet response: {e}"}
    except Exception as e:
        print(f"[read_property] Exception: {e}")
        return {"status": "error", "error": str(e)}

@app.post("/ping_ip")
async def ping_ip(ip_address: str = Form(...)):
    """
    Ping the given IP address and return the result. Waits for a response, shows loading in UI until done.
    """
    # Use the system ping command for cross-platform compatibility
    # -c 1: send 1 packet (Linux/macOS), -W 2: 2 second timeout
    # For Windows, use '-n 1' and '-w 2000' (ms)
    import platform
    import asyncio
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", "2000", ip_address]
    else:
        cmd = ["ping", "-c", "1", "-W", "2", ip_address]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        success = proc.returncode == 0
        result = stdout.decode() if stdout else stderr.decode()
        return {
            "ip_address": ip_address,
            "success": success,
            "output": result.strip()
        }
    except Exception as e:
        return {
            "ip_address": ip_address,
            "success": False,
            "error": str(e)
        }

@app.post("/bacnet/scan_ip_range")
async def scan_ip_range(network_str: str = Form(...)):
    """
    Scan a range of IPs for BACnet devices.
    """
    manager = app.state.bacnet_manager
    proxy_id = manager.ppm.get_proxy_id((BACNET_PROXY_LOCAL_ADDRESS, 0))
    peer = manager.ppm.peers.get(proxy_id)
    if not peer or not peer.socket_params:
        return {"status": "error", "error": "Proxy not registered or missing, cannot scan."}
    from protocol_proxy.ipc import ProtocolProxyMessage
    import json
    payload = {"network_str": network_str}
    result = await manager.ppm.send(peer.socket_params, ProtocolProxyMessage(
        method_name="SCAN_IP_RANGE",
        payload=json.dumps(payload).encode('utf8'),
        response_expected=True
    ))
    if asyncio.isfuture(result):
        result = await result
    try:
        value = json.loads(result.decode('utf8'))
        return {"status": "done", "devices": value}
    except Exception as e:
        return {"status": "error", "error": f"Error decoding scan_ip_range response: {e}"}

@app.post("/bacnet/read_device_all")
async def read_device_all(
    device_address: str = Form(...),
    device_object_identifier: str = Form(...)
):
    """
    Read all standard properties from a BACnet device.
    """
    manager = app.state.bacnet_manager
    proxy_id = manager.ppm.get_proxy_id((BACNET_PROXY_LOCAL_ADDRESS, 0))
    peer = manager.ppm.peers.get(proxy_id)
    if not peer or not peer.socket_params:
        return {"status": "error", "error": "Proxy not registered or missing, cannot read device."}
    from protocol_proxy.ipc import ProtocolProxyMessage
    import json
    payload = {
        "device_address": device_address,
        "device_object_identifier": device_object_identifier
    }
    result = await manager.ppm.send(peer.socket_params, ProtocolProxyMessage(
        method_name="READ_DEVICE_ALL",
        payload=json.dumps(payload).encode('utf8'),
        response_expected=True
    ))
    if asyncio.isfuture(result):
        result = await result
    try:
        value = json.loads(result.decode('utf8'))
        return {"status": "done", "properties": value}
    except Exception as e:
        return {"status": "error", "error": f"Error decoding read_device_all response: {e}"}

#TODO create callbacks
@app.post("/bacnet/who_is")
async def who_is(
    device_instance_low: int = Form(...),
    device_instance_high: int = Form(...),
    dest: str = Form(...)
):
    """
    Send a Who-Is request to a BACnet address or range.
    """
    manager = app.state.bacnet_manager
    proxy_id = manager.ppm.get_proxy_id((BACNET_PROXY_LOCAL_ADDRESS, 0))
    peer = manager.ppm.peers.get(proxy_id)
    if not peer or not peer.socket_params:
        return {"status": "error", "error": "Proxy not registered or missing, cannot send Who-Is."}
    from protocol_proxy.ipc import ProtocolProxyMessage
    import json
    payload = {
        "device_instance_low": device_instance_low,
        "device_instance_high": device_instance_high,
        "dest": dest
    }
    result = await manager.ppm.send(peer.socket_params, ProtocolProxyMessage(
        method_name="WHO_IS",
        payload=json.dumps(payload).encode('utf8'),
        response_expected=True
    ))
    if asyncio.isfuture(result):
        result = await result
    try:
        value = json.loads(result.decode('utf8'))
        return {"status": "done", "devices": value}
    except Exception as e:
        return {"status": "error", "error": f"Error decoding who_is response: {e}"}
# Temporary stubs to avoid NameError in endpoints
# TODO: Replace with real device/point discovery logic

device_points = {}
point_tags = {}
