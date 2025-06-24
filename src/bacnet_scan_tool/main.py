import asyncio
import json
import uuid
from typing import Optional, Any
import socket

from fastapi import FastAPI, HTTPException, Depends, Form, Query
from fastapi.responses import JSONResponse
from sqlmodel import SQLModel, Session, create_engine, select
from pydantic import BaseModel

from protocol_proxy.bacnet_manager import AsyncioBACnetManager
from protocol_proxy.manager import ProtocolProxyManager
from protocol_proxy.bacnet_proxy import BACnetProxy
from protocol_proxy.ipc import ProtocolProxyMessage

from .models import Device, Point, Tag, CreateTagRequest, WritePointValueRequest



# TODO handle who is AND just one device.
# TODO return device / object identifier in scan ip range
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

@app.post("/bacnet/scan_ip_range")
async def scan_ip_range(network_str: str = Form(...)):
    """
    Scan a range of IPs for BACnet devices using brute-force Who-Is.
    Ensures each device result includes 'device_instance' (int), 'object-name', and a string 'deviceIdentifier'.
    """
    manager = app.state.bacnet_manager
    local_addr = app.state.bacnet_proxy_local_address
    proxy_id = manager.ppm.get_proxy_id((local_addr, 0))
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
        # Post-process to ensure device_instance and string deviceIdentifier
        processed = []
        for dev in value:
            dev_out = dict(dev)
            # device_instance
            if 'device_instance' not in dev_out:
                # Try to extract from deviceIdentifier
                did = dev_out.get('deviceIdentifier')
                if isinstance(did, (list, tuple)) and len(did) == 2:
                    dev_out['device_instance'] = did[1]
            # deviceIdentifier as string
            if 'deviceIdentifier' in dev_out:
                did = dev_out['deviceIdentifier']
                if isinstance(did, (list, tuple)):
                    dev_out['deviceIdentifier'] = f"{did[0]},{did[1]}"
            processed.append(dev_out)
        return {"status": "done", "devices": processed}
    except Exception as e:
        return {"status": "error", "error": f"Error decoding scan_ip_range response: {e}"}

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
    
@app.post("/bacnet/one_click_discovery")
async def one_click_discovery():
    """
    Perform a one-click discovery of BACnet devices:
    - Selects the best local interface (non-loopback, with subnet mask)
    - Starts the BACnet proxy with that interface
    - Gets the Windows host IP (for WSL2)
    - Runs scan_ip_range on that IP's /20 subnet (TODO: make subnet detection smarter)
    - Returns the selected IP, subnet, proxy status, and scan results
    """
    import netifaces
    import ipaddress
    import subprocess
    import re
    # Step 1: Find the best local interface
    selected_ip = None
    selected_mask = None
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                ip = addr.get('addr')
                mask = addr.get('netmask')
                if ip and mask and not ip.startswith('127.'):
                    selected_ip = ip
                    selected_mask = mask
                    break
        if selected_ip:
            break
    if not selected_ip or not selected_mask:
        return {"status": "error", "error": "No suitable local interface found."}
    # Step 2: Calculate CIDR
    net = ipaddress.IPv4Network(f"{selected_ip}/{selected_mask}", strict=False)
    cidr = f"{selected_ip}/{net.prefixlen}"
    # Step 3: Start the proxy with this IP
    try:
        if hasattr(app.state, "bacnet_manager_task") and app.state.bacnet_manager_task:
            app.state.bacnet_manager_task.cancel()
            await asyncio.sleep(0.5)
        app.state.bacnet_manager = AsyncioBACnetManager(selected_ip)
        app.state.bacnet_manager_task = asyncio.create_task(app.state.bacnet_manager.run())
        app.state.bacnet_proxy_local_address = selected_ip
        await asyncio.sleep(3)
        manager = app.state.bacnet_manager
        proxy_id = manager.ppm.get_proxy_id((selected_ip, 0))
        peer = manager.ppm.peers.get(proxy_id)
        if not peer or not peer.socket_params:
            return {"status": "error", "error": "Proxy not registered or missing socket_params."}
        # Step 4: Get Windows host IP (for WSL2)
        try:
            output = subprocess.check_output(["ipconfig.exe"], encoding="utf-8", errors="ignore")
            # Find all IPv4 addresses and subnet masks
            ip_matches = list(re.finditer(r"IPv4 Address[. ]*: ([0-9.]+)", output))
            mask_matches = list(re.finditer(r"Subnet Mask[. ]*: ([0-9.]+)", output))
            windows_ip = None
            windows_mask = None
            # Try to pair IPs and masks by order
            for idx, ip_match in enumerate(ip_matches):
                ip = ip_match.group(1)
                if not (ip.startswith("127.") or ip.startswith("172.") or ip.startswith("192.168.56.")):
                    windows_ip = ip
                    # Try to get the corresponding mask
                    if idx < len(mask_matches):
                        windows_mask = mask_matches[idx].group(1)
                    break
            if not windows_ip and ip_matches:
                windows_ip = ip_matches[0].group(1)
                if mask_matches:
                    windows_mask = mask_matches[0].group(1)
        except Exception:
            windows_ip = None
            windows_mask = None
        # Step 5: Run scan_ip_range on Windows IP's /20 subnet (use correct mask if available)
        scan_result = None
        scan_cidr = None  # Ensure scan_cidr is always defined
        if windows_ip:
            # TODO: Make subnet detection smarter than /20
            base = ".".join(windows_ip.split(".")[:3])
            scan_cidr = f"{base}.0/20"
            scan_result = await scan_ip_range(network_str=scan_cidr)
        return {
            "status": "done",
            "local_ip": selected_ip,
            "subnet_mask": selected_mask,
            "cidr": cidr,
            "windows_host_ip": windows_ip,
            "scan_range": scan_cidr if windows_ip else None,
            "scan_result": scan_result
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}

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


# TODO having problems with this endpoint, it is not working as expected
# @app.post("/bacnet/who_is_router_to_network_targeted")
# async def whois_router_to_network_targeted(
#     my_ip: str = Form(..., description="Local interface with subnet mask, e.g. '192.168.1.10/24'"),
#     target_ip: str = Form(..., description="The device you want to scan (IP address)"),
#     bbmd_ip: str = Form(None, description="Remote BBMD (if needed), e.g. '130.20.24.157:47808'"),
#     bbmd_ttl: int = Form(900, description="BBMD TTL (default 900)")
# ):
#     """
#     Mimics the script logic: Who-Is to a target device, then Who-Is-Router-To-Network if found.
#     Returns found devices and routing table.
#     """
#     import BAC0
#     bacnet = None
#     try:
#         # Start BAC0 with local IP and optional BBMD
#         if bbmd_ip:
#             bacnet = BAC0.lite(ip=my_ip, bbmdAddress=bbmd_ip, bbmdTTL=bbmd_ttl)
#         else:
#             bacnet = BAC0.lite(ip=my_ip)
#         await asyncio.sleep(1)
#         # Send Who-Is to the target device
#         devices = await bacnet.who_is(address=target_ip)
#         found_devices = []
#         if devices:
#             for device in devices:
#                 device_id = device.iAmDeviceIdentifier[1]
#                 found_devices.append({
#                     "device_id": device_id,
#                     "address": str(device.address),
#                     "max_apdu_length": getattr(device, 'maxAPDULengthAccepted', None),
#                     "segmentation_supported": str(getattr(device, 'segmentationSupported', None)),
#                 })
#             # Try router discovery
#             await bacnet.whois_router_to_network(0)
#             routing_table = getattr(bacnet, 'routing_table', None)
#             return {"status": "done", "devices": found_devices, "routing_table": routing_table}
#         else:
#             return {"status": "done", "devices": [], "routing_table": None, "message": f"No BACnet devices found at {target_ip}."}
#     except Exception as e:
#         return {"status": "error", "error": str(e)}
#     finally:
#         if bacnet is not None:
#             try:
#                 bacnet.close()
#                 await asyncio.sleep(1)
#             except Exception:
#                 pass

@app.post("/stop_proxy")
async def stop_proxy():
    """
    Stop the running BACnet proxy and clean up state.
    """
    try:
        if hasattr(app.state, "bacnet_manager_task") and app.state.bacnet_manager_task:
            app.state.bacnet_manager_task.cancel()
            await asyncio.sleep(0.5)
            app.state.bacnet_manager_task = None
        if hasattr(app.state, "bacnet_manager"):
            app.state.bacnet_manager = None
        if hasattr(app.state, "bacnet_proxy_local_address"):
            app.state.bacnet_proxy_local_address = None
        return {"status": "done", "message": "BACnet proxy stopped."}
    except Exception as e:
        return {"status": "error", "error": str(e)}

@app.get("/get_local_ip")
def get_local_ip(target_ip: str = Query(..., description="Target IP address")):
    """
    Returns the local IP, subnet mask, and CIDR notation for the interface used to reach the target IP.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target_ip, 80))
        local_ip = s.getsockname()[0]
        s.close()
        try:
            import netifaces
            iface_name = None
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        if addr.get('addr') == local_ip:
                            iface_name = iface
                            subnet_mask = addr.get('netmask')
                            break
                if iface_name:
                    break
            if iface_name and subnet_mask:
                # Calculate CIDR
                import ipaddress
                net = ipaddress.IPv4Network(f"{local_ip}/{subnet_mask}", strict=False)
                cidr = f"{local_ip}/{net.prefixlen}"
                return {"local_ip": local_ip, "subnet_mask": subnet_mask, "cidr": cidr}
            else:
                return {"local_ip": local_ip, "error": "Could not determine subnet mask for this interface."}
        except ImportError:
            return {"local_ip": local_ip, "error": "netifaces package not installed. Install with 'pip install netifaces' to get subnet mask and CIDR."}
    except Exception:
        return {"local_ip": "127.0.0.1", "error": "Could not determine local IP."}

@app.get("/get_windows_host_ip")
def get_windows_host_ip():
    """
    Returns the first non-loopback IPv4 address from the Windows host (for WSL2 environments).
    """
    import subprocess
    import re
    try:
        output = subprocess.check_output(["ipconfig.exe"], encoding="utf-8", errors="ignore")
        ips = re.findall(r"IPv4 Address[. ]*: ([0-9.]+)", output)
        for ip in ips:
            if not (ip.startswith("127.") or ip.startswith("172.") or ip.startswith("192.168.56.")):
                return {"windows_host_ip": ip}
        if ips:
            return {"windows_host_ip": ips[0]}
        return {"error": "Could not determine Windows host IPv4 address."}
    except Exception:
        return {"error": "Could not determine Windows host IPv4 address."}
