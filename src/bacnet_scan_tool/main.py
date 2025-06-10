import asyncio
import json
import uuid
from typing import Optional, Any

from fastapi import FastAPI, HTTPException, Depends, Form, Query, Body
from fastapi.responses import JSONResponse  # <-- Added import
from sqlmodel import SQLModel, Session, create_engine, select

from . models import Device, Point, Tag, CreateTagRequest, WritePointValueRequest



# TODO handle who is AND just one device.
app = FastAPI()

# SQLite database setup
DATABASE_URL = "sqlite:///./bacnet.db"
engine = create_engine(DATABASE_URL)

@app.on_event("startup")
async def on_startup():
    SQLModel.metadata.create_all(engine)
    # Do not start the proxy here anymore
    pass

@app.post("/start_proxy")
async def start_proxy(local_device_address: str = Form(...)):
    """
    Start the BACnet proxy with the given local device address (IP).
    Returns status and address.
    """
    from protocol_proxy.bacnet_manager import AsyncioBACnetManager
    try:
        # If a proxy is already running, stop it first
        if hasattr(app.state, "bacnet_manager_task") and app.state.bacnet_manager_task:
            app.state.bacnet_manager_task.cancel()
            await asyncio.sleep(0.5)
        app.state.bacnet_manager = AsyncioBACnetManager(local_device_address)
        app.state.bacnet_manager_task = asyncio.create_task(app.state.bacnet_manager.run())
        app.state.bacnet_proxy_local_address = local_device_address  # Save the address for later use
        # Wait a bit for registration
        await asyncio.sleep(3)
        # Check registration
        manager = app.state.bacnet_manager
        proxy_id = manager.ppm.get_proxy_id((local_device_address, 0))
        peer = manager.ppm.peers.get(proxy_id)
        if not peer or not peer.socket_params:
            return {"status": "error", "error": "Proxy not registered or missing socket_params."}
        return {"status": "done", "address": local_device_address}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def get_session():
    with Session(engine) as session:
        yield session

@app.post("/write_property")
async def write_property(device_address: str, object_identifier: str, property_identifier: str, value: Any,
                         priority: int, property_array_index: int = None):
    """
    Write a value to a specific property of a device point.
    """
    from protocol_proxy.manager import ProtocolProxyManager
    from protocol_proxy.bacnet_proxy import BACnetProxy
    from protocol_proxy.ipc import ProtocolProxyMessage
    import json
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
        local_addr = app.state.bacnet_proxy_local_address
        proxy_id = manager.ppm.get_proxy_id((local_addr, 0))
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

# @app.post("/bacnet/scan_ip_range")
# async def scan_ip_range(network_str: str = Form(...)):
#     """
#     Scan a range of IPs for BACnet devices.
#     """
#     manager = app.state.bacnet_manager
#     proxy_id = manager.ppm.get_proxy_id((BACNET_PROXY_LOCAL_ADDRESS, 0))
#     peer = manager.ppm.peers.get(proxy_id)
#     if not peer or not peer.socket_params:
#         return {"status": "error", "error": "Proxy not registered or missing, cannot scan."}
#     from protocol_proxy.ipc import ProtocolProxyMessage
#     import json
#     payload = {"network_str": network_str}
#     result = await manager.ppm.send(peer.socket_params, ProtocolProxyMessage(
#         method_name="SCAN_IP_RANGE",
#         payload=json.dumps(payload).encode('utf8'),
#         response_expected=True
#     ))
#     if asyncio.isfuture(result):
#         result = await result
#     try:
#         value = json.loads(result.decode('utf8'))
#         return {"status": "done", "devices": value}
#     except Exception as e:
#         return {"status": "error", "error": f"Error decoding scan_ip_range response: {e}"}

def make_jsonable(obj):
    """
    Recursively convert BACnet objects, enums, and tuples to JSON-serializable types.
    """
    import ipaddress
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, bytes):
        return obj.decode('utf-8', errors='replace')
    if isinstance(obj, bytearray):
        return bytes(obj).decode('utf-8', errors='replace')
    if isinstance(obj, dict):
        return {make_jsonable(k): make_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, set, tuple)):
        return [make_jsonable(x) for x in obj]
    if hasattr(obj, 'name') and hasattr(obj, 'value'):
        # Likely an enum
        return str(obj.name)
    if hasattr(obj, '__class__') and obj.__class__.__name__.startswith('ObjectType'):
        return str(obj)
    if isinstance(obj, ipaddress.IPv4Address) or isinstance(obj, ipaddress.IPv6Address):
        return str(obj)
    # Fallback to string
    return str(obj)

@app.post("/bacnet/read_device_all")
async def read_device_all(
    device_address: str = Form(...),
    device_object_identifier: str = Form(...)
):
    """
    Read all standard properties from a BACnet device.
    """
    manager = app.state.bacnet_manager
    local_addr = app.state.bacnet_proxy_local_address
    proxy_id = manager.ppm.get_proxy_id((local_addr, 0))
    peer = manager.ppm.peers.get(proxy_id)
    if not peer or not peer.socket_params:
        return JSONResponse(content={"status": "error", "error": "Proxy not registered or missing, cannot read device."}, status_code=500)
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
    print(f"[read_device_all] Raw result bytes: {result}")
    try:
        value = json.loads(result.decode('utf8'))
        jsonable = make_jsonable(value)
        print(f"[read_device_all FastAPI] Returning to frontend: {jsonable}", 50 * "*")
        return JSONResponse(content={"status": "done", "properties": jsonable})
    except Exception as e:
        print(f"[read_device_all] Error decoding or serializing response: {e}")
        return JSONResponse(content={"status": "error", "error": f"Error decoding read_device_all response: {e}"}, status_code=500)

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
    local_addr = app.state.bacnet_proxy_local_address
    proxy_id = manager.ppm.get_proxy_id((local_addr, 0))
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
