import asyncio
import json
import socket
from typing import Optional, Any

from fastapi import FastAPI, HTTPException, Depends, Form, Query
from sqlmodel import SQLModel, Session, create_engine, select

from protocol_proxy.bacnet_manager import AsyncioBACnetManager
from protocol_proxy.manager import ProtocolProxyManager
from protocol_proxy.bacnet_proxy import BACnetProxy
from protocol_proxy.ipc import ProtocolProxyMessage

from .models import (
    IPAddress, LocalIPResponse, ProxyResponse, ScanResponse, 
    PropertyReadResponse, DevicePropertiesResponse, WhoIsResponse, PingResponse
)

# TODO handle who is AND just one device.
app = FastAPI()

# SQLite database setup
DATABASE_URL = "sqlite:///./bacnet.db"
engine = create_engine(DATABASE_URL)


@app.on_event("startup")
async def on_startup():
    SQLModel.metadata.create_all(engine)
    pass


@app.get("/get_local_ip", response_model=LocalIPResponse)
def get_local_ip(target_ip: Optional[str] = Query(
    None,
    description=
    "Optional. If provided, returns the local IP/interface that would be used to reach this target IP (useful for multi-homed systems). If not provided, defaults to 8.8.8.8 (internet route)."
)):
    """
    Returns the local IP, subnet mask, and CIDR notation for the interface used to reach the target IP.
    If no target_ip is provided, defaults to 8.8.8.8 to determine the main outbound interface.
    """
    try:
        # Use 8.8.8.8 as the default target if not provided
        effective_target = target_ip if target_ip else "8.8.8.8"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((effective_target, 80))
        local_ip = s.getsockname()[0]
        s.close()
        # Now, get subnet mask and CIDR
        try:
            import netifaces
            iface_name = None
            subnet_mask = None
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
                import ipaddress
                net = ipaddress.IPv4Network(f"{local_ip}/{subnet_mask}",
                                            strict=False)
                cidr = f"{local_ip}/{net.prefixlen}"
                return LocalIPResponse(
                    local_ip=local_ip,
                    subnet_mask=subnet_mask,
                    cidr=cidr
                )
            else:
                return LocalIPResponse(
                    local_ip=local_ip,
                    error="Could not determine subnet mask for this interface."
                )
        except ImportError:
            return LocalIPResponse(
                local_ip=local_ip,
                error="netifaces package not installed. Install with 'pip install netifaces' to get subnet mask and CIDR."
            )
    except Exception:
        return LocalIPResponse(
            local_ip="127.0.0.1",
            error="Could not determine local IP."
        )


@app.post("/start_proxy", response_model=ProxyResponse)
async def start_proxy(local_device_address: Optional[str] = Form(None)):
    """
    Start the BACnet proxy with the given local device address (IP), or auto-detect if not provided.
    Returns status and address.
    """
    try:
        # If no address provided, auto-detect using get_local_ip logic
        if not local_device_address:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_device_address = s.getsockname()[0]
                s.close()
            except Exception:
                return ProxyResponse(
                    status="error",
                    error="Could not auto-detect local IP address. Please specify manually."
                )
        # If a proxy is already running, stop it first
        if hasattr(app.state,
                   "bacnet_manager_task") and app.state.bacnet_manager_task:
            app.state.bacnet_manager_task.cancel()
            await asyncio.sleep(0.5)
        app.state.bacnet_manager = AsyncioBACnetManager(local_device_address)
        app.state.bacnet_manager_task = asyncio.create_task(
            app.state.bacnet_manager.run())
        app.state.bacnet_proxy_local_address = local_device_address  # Save the address for later use
        # Wait a bit for registration
        await asyncio.sleep(3)
        # Check registration
        manager = app.state.bacnet_manager
        proxy_id = manager.ppm.get_proxy_id((local_device_address, 0))
        peer = manager.ppm.peers.get(proxy_id)
        if not peer or not peer.socket_params:
            return ProxyResponse(
                status="error",
                error="Proxy not registered or missing socket_params."
            )
        return ProxyResponse(status="done", address=local_device_address)
    except Exception as e:
        return ProxyResponse(status="error", error=str(e))


@app.get("/get_host_ip", response_model=IPAddress)
def get_host_ip():
    """
    Returns the first non-loopback IPv4 address. Works on both WSL and native Linux systems.
    For WSL: attempts to get Windows host IP via ipconfig.exe
    For native Linux: returns the primary network interface IP
    """
    import subprocess
    import re
    import os
    import platform
    
    # First, try WSL method (ipconfig.exe)
    try:
        # Check if we're in WSL by looking for ipconfig.exe availability
        subprocess.check_output(["which", "ipconfig.exe"], 
                               stderr=subprocess.DEVNULL)
        # We're in WSL, use the original method
        output = subprocess.check_output(["ipconfig.exe"],
                                         encoding="utf-8",
                                         errors="ignore")
        ips = re.findall(r"IPv4 Address[. ]*: ([0-9.]+)", output)
        for ip in ips:
            if not (ip.startswith("127.") or ip.startswith("172.")
                    or ip.startswith("192.168.56.")):
                return IPAddress(address=ip)
        if ips:
            return IPAddress(address=ips[0])
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Not in WSL or ipconfig.exe not available, try Linux methods
        pass
    
    # Native Linux method - try multiple approaches
    try:
        # Method 1: Use ip route to find default gateway interface IP
        try:
            # Get the default route interface
            route_output = subprocess.check_output(
                ["ip", "route", "show", "default"], 
                encoding="utf-8"
            )
            # Extract interface name from default route
            import re
            match = re.search(r'dev\s+(\S+)', route_output)
            if match:
                interface = match.group(1)
                # Get IP of that interface
                addr_output = subprocess.check_output(
                    ["ip", "addr", "show", interface],
                    encoding="utf-8"
                )
                ip_match = re.search(r'inet\s+([0-9.]+)', addr_output)
                if ip_match:
                    ip = ip_match.group(1)
                    if not ip.startswith("127."):
                        return IPAddress(address=ip)
        except (subprocess.CalledProcessError, AttributeError):
            pass

        # Method 2: Use hostname -I as fallback
        try:
            output = subprocess.check_output(["hostname", "-I"], 
                                           encoding="utf-8")
            ips = output.strip().split()
            for ip in ips:
                if not (ip.startswith("127.") or ip.startswith("172.")
                        or ip.startswith("192.168.56.")):
                    return IPAddress(address=ip)
            if ips:
                return IPAddress(address=ips[0])
        except subprocess.CalledProcessError:
            pass
        
        # Method 3: Parse /proc/net/route as last resort
        try:
            with open('/proc/net/route', 'r') as f:
                for line in f:
                    fields = line.strip().split()
                    if len(fields) >= 2 and fields[1] == '00000000':  # Default route
                        interface = fields[0]
                        # Get IP for this interface
                        addr_output = subprocess.check_output(
                            ["ip", "addr", "show", interface],
                            encoding="utf-8"
                        )
                        ip_match = re.search(r'inet\s+([0-9.]+)', addr_output)
                        if ip_match:
                            ip = ip_match.group(1)
                            if not ip.startswith("127."):
                                return IPAddress(address=ip)
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass
        
        # If we get here, we couldn't find any IP
        raise HTTPException(status_code=500, detail="Could not determine host IPv4 address on this system.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not determine host IPv4 address: {str(e)}")


@app.post("/bacnet/scan_subnet", response_model=ScanResponse)
async def scan_subnet(subnet: str = Form(...)):
    """
    Scan a subnet (CIDR notation, e.g. 192.168.1.0/24) for BACnet devices using brute-force Who-Is.
    Ensures each device result includes 'device_instance', 'object_name', 'deviceIdentifier', and extra BACnet info.
    """
    manager = app.state.bacnet_manager
    local_addr = app.state.bacnet_proxy_local_address
    proxy_id = manager.ppm.get_proxy_id((local_addr, 0))
    peer = manager.ppm.peers.get(proxy_id)
    if not peer or not peer.socket_params:
        # Calculate number of IPs in the subnet for error case
        import ipaddress
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            ips_scanned = net.num_addresses - 2 if net.num_addresses > 2 else net.num_addresses
        except Exception:
            ips_scanned = 0
        return ScanResponse(
            status="error",
            error="Proxy not registered or missing, cannot scan.",
            ips_scanned=ips_scanned
        )
    from protocol_proxy.ipc import ProtocolProxyMessage
    import json
    payload = {"network_str": subnet}
    # Calculate number of IPs in the subnet
    import ipaddress
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        ips_scanned = net.num_addresses - 2 if net.num_addresses > 2 else net.num_addresses
    except Exception:
        ips_scanned = 0
    result = await manager.ppm.send(
        peer.socket_params,
        ProtocolProxyMessage(method_name="SCAN_SUBNET",
                             payload=json.dumps(payload).encode('utf8'),
                             response_expected=True))
    if asyncio.isfuture(result):
        result = await result
    try:
        value = json.loads(result.decode('utf8'))

        # Check if this is a timeout error response
        if isinstance(value, dict) and value.get(
                'status') == 'error' and 'timed out' in value.get('error', ''):
            return ScanResponse(
                status="error",
                error=f"Scan operation timed out: {value.get('error', 'Unknown timeout error')}",
                ips_scanned=ips_scanned
            )

        # Only return the minimal Who-Is/I-Am response data for each device
        from .models import BACnetDevice
        processed = []
        for dev in value:
            dev_out = {}
            # Only keep the fields from the I-Am response
            for k in ["pduSource", "deviceIdentifier", "maxAPDULengthAccepted", "segmentationSupported", "vendorID"]:
                if k in dev:
                    dev_out[k] = dev[k]
            # Fix deviceIdentifier and device_instance for BACnetDevice model
            did = dev_out.get("deviceIdentifier")
            if isinstance(did, (list, tuple)) and len(did) == 2:
                dev_out["device_instance"] = did[1]
                dev_out["deviceIdentifier"] = f"{did[0]},{did[1]}"
            # Extract IP address from pduSource (if present)
            pdu_source = dev.get("pduSource")
            if isinstance(pdu_source, str):
                # If pduSource is an IP:port string, extract just the IP
                if ":" in pdu_source:
                    dev_out["address"] = pdu_source.split(":")[0]
                else:
                    dev_out["address"] = pdu_source
            else:
                dev_out["address"] = None
            processed.append(BACnetDevice(**dev_out))
        return ScanResponse(status="done", devices=processed, ips_scanned=ips_scanned)
    except json.JSONDecodeError as e:
        result_str = result.decode('utf8', errors='replace') if isinstance(result, bytes) else str(result)
        if not result_str or result_str.strip() == 'FOO':
            return ScanResponse(
                status="error",
                error="Scan operation timed out - no response received from BACnet proxy",
                ips_scanned=ips_scanned
            )
        return ScanResponse(
            status="error",
            error=f"Error decoding scan_ip_range response: {e}. Raw response: {result_str[:200]}",
            ips_scanned=ips_scanned
        )
    except Exception as e:
        return ScanResponse(
            status="error",
            error=f"Error processing scan_ip_range response: {e}",
            ips_scanned=ips_scanned
        )


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
    if hasattr(
            obj,
            '__class__') and obj.__class__.__name__.startswith('ObjectType'):
        return str(obj)
    if isinstance(obj, ipaddress.IPv4Address) or isinstance(
            obj, ipaddress.IPv6Address):
        return str(obj)
    # Fallback to string
    return str(obj)


def get_session():
    with Session(engine) as session:
        yield session


@app.post("/write_property")
async def write_property(device_address: str,
                         object_identifier: str,
                         property_identifier: str,
                         value: Any,
                         priority: int,
                         property_array_index: int = None):
    """
    Write a value to a specific property of a device point.
    """
    ppm = ProtocolProxyManager.get_manager(BACnetProxy)
    message = ProtocolProxyMessage(method_name="WRITE_PROPERTY",
                                   payload=json.dumps({
                                       "device_address":
                                       device_address,
                                       "object_identifier":
                                       object_identifier,
                                       "property_identifier":
                                       property_identifier,
                                       "value":
                                       value,
                                       "priority":
                                       priority,
                                       "property_array_index":
                                       property_array_index
                                   }).encode('utf8'))

    remote_params = ppm.peers.socket_params
    send_result = await ppm.send(remote_params, message)
    print("Sent WRITE_PROPERTY message")

    return send_result


@app.post("/read_property", response_model=PropertyReadResponse)
async def read_property(device_address: str = Form(...),
                        object_identifier: str = Form(...),
                        property_identifier: str = Form(...),
                        property_array_index: Optional[int] = Form(None)):
    """
    Perform a BACnet property read and return the result directly (waits for completion).
    """
    print(
        "[read_property] Using global AsyncioBACnetManager from app.state...")
    try:
        manager = app.state.bacnet_manager
        local_addr = app.state.bacnet_proxy_local_address
        proxy_id = manager.ppm.get_proxy_id((local_addr, 0))
        peer = manager.ppm.peers.get(proxy_id)
        if not peer or not peer.socket_params:
            print(
                "[read_property] Proxy not registered or missing socket_params!"
            )
            return PropertyReadResponse(
                status="error",
                error="Proxy not registered or missing socket_params, cannot send request."
            )
        payload = {
            'device_address': device_address,
            'object_identifier': object_identifier,
            'property_identifier': property_identifier
        }
        if property_array_index is not None:
            payload['property_array_index'] = property_array_index
        print(f"[read_property] Sending ProtocolProxyMessage: {payload}")

        result = await manager.ppm.send(
            peer.socket_params,
            ProtocolProxyMessage(method_name='READ_PROPERTY',
                                 payload=json.dumps(payload).encode('utf8'),
                                 response_expected=True))
        print("[read_property] Got result from send()")
        if asyncio.isfuture(result):
            print("[read_property] Result is a Future, awaiting...")
            result = await result
        print(f"[read_property] Raw result: {result}")
        try:
            value = json.loads(result.decode('utf8'))
            print(f"[read_property] Decoded value: {value}")
            # --- Normalization logic for response ---
            # If property is 'object-name', return {"object_name": ...}
            # If value is {"_value": ...}, return just the value
            normalized = value
            if property_identifier.lower().replace("-", "_") == "object_name":
                # Accept both 'object-name' and 'object_name'
                if isinstance(value, dict):
                    # Try to extract from common keys
                    for k in ["object-name", "object_name", "_value", "value"]:
                        if k in value:
                            normalized = {"object_name": value[k]}
                            break
                    else:
                        normalized = {"object_name": value}
                else:
                    normalized = {"object_name": value}
            elif isinstance(value, dict) and set(value.keys()) == {"_value"}:
                normalized = value["_value"]
            return PropertyReadResponse(status="done", result=normalized)
        except Exception as e:
            print(f"[read_property] Error decoding BACnet response: {e}")
            return PropertyReadResponse(
                status="error",
                error=f"Error decoding BACnet response: {e}"
            )
    except Exception as e:
        print(f"[read_property] Exception: {e}")
        return PropertyReadResponse(status="error", error=str(e))


@app.post("/bacnet/read_device_all", response_model=DevicePropertiesResponse)
async def read_device_all(device_address: str = Form(...),
                          device_object_identifier: str = Form(...)):
    """
    Read all standard properties from a BACnet device.
    """
    manager = app.state.bacnet_manager
    local_addr = app.state.bacnet_proxy_local_address
    proxy_id = manager.ppm.get_proxy_id((local_addr, 0))
    peer = manager.ppm.peers.get(proxy_id)
    if not peer or not peer.socket_params:
        return DevicePropertiesResponse(
            status="error",
            error="Proxy not registered or missing, cannot read device."
        )
    from protocol_proxy.ipc import ProtocolProxyMessage
    import json
    payload = {
        "device_address": device_address,
        "device_object_identifier": device_object_identifier
    }
    result = await manager.ppm.send(
        peer.socket_params,
        ProtocolProxyMessage(method_name="READ_DEVICE_ALL",
                             payload=json.dumps(payload).encode('utf8'),
                             response_expected=True))
    if asyncio.isfuture(result):
        result = await result
    print(f"[read_device_all] Raw result bytes: {result}")
    try:
        value = json.loads(result.decode('utf8'))
        jsonable = make_jsonable(value)
        print(f"[read_device_all FastAPI] Returning to frontend: {jsonable}",
              50 * "*")
        return DevicePropertiesResponse(status="done", properties=jsonable)
    except Exception as e:
        print(f"[read_device_all] Error decoding or serializing response: {e}")
        return DevicePropertiesResponse(
            status="error",
            error=f"Error decoding read_device_all response: {e}"
        )


#TODO create callbacks
@app.post("/bacnet/who_is", response_model=WhoIsResponse)
async def who_is(device_instance_low: int = Form(...),
                 device_instance_high: int = Form(...),
                 dest: str = Form(...)):
    """
    Send a Who-Is request to a BACnet address or range.
    """
    manager = app.state.bacnet_manager
    local_addr = app.state.bacnet_proxy_local_address
    proxy_id = manager.ppm.get_proxy_id((local_addr, 0))
    peer = manager.ppm.peers.get(proxy_id)
    if not peer or not peer.socket_params:
        return WhoIsResponse(
            status="error",
            error="Proxy not registered or missing, cannot send Who-Is."
        )
    from protocol_proxy.ipc import ProtocolProxyMessage
    import json
    payload = {
        "device_instance_low": device_instance_low,
        "device_instance_high": device_instance_high,
        "dest": dest
    }
    result = await manager.ppm.send(
        peer.socket_params,
        ProtocolProxyMessage(method_name="WHO_IS",
                             payload=json.dumps(payload).encode('utf8'),
                             response_expected=True))
    if asyncio.isfuture(result):
        result = await result
    try:
        value = json.loads(result.decode('utf8'))
        return WhoIsResponse(status="done", devices=value)
    except Exception as e:
        return WhoIsResponse(
            status="error",
            error=f"Error decoding who_is response: {e}"
        )


# Temporary stubs to avoid NameError in endpoints

device_points = {}
point_tags = {}


@app.post("/ping_ip", response_model=PingResponse)
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
            stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await proc.communicate()
        success = proc.returncode == 0
        result = stdout.decode() if stdout else stderr.decode()
        return PingResponse(
            ip_address=ip_address,
            success=success,
            output=result.strip()
        )
    except Exception as e:
        return PingResponse(
            ip_address=ip_address,
            success=False,
            error=str(e)
        )


@app.post("/stop_proxy", response_model=ProxyResponse)
async def stop_proxy():
    """
    Stop the running BACnet proxy and clean up state.
    """
    try:
        if hasattr(app.state,
                   "bacnet_manager_task") and app.state.bacnet_manager_task:
            app.state.bacnet_manager_task.cancel()
            await asyncio.sleep(0.5)
            app.state.bacnet_manager_task = None
        if hasattr(app.state, "bacnet_manager"):
            app.state.bacnet_manager = None
        if hasattr(app.state, "bacnet_proxy_local_address"):
            app.state.bacnet_proxy_local_address = None
        return ProxyResponse(status="done", message="BACnet proxy stopped.")
    except Exception as e:
        return ProxyResponse(status="error", error=str(e))

from fastapi.responses import JSONResponse
# TODO make it handle larger responsese from the proxy and implement model
@app.post("/bacnet/read_object_list_names")
async def read_object_list_names(device_address: str = Form(...), device_object_identifier: str = Form(...)):
    """
    Reads the object-list from a device, then reads object-name for each object in the list.
    Returns a dict mapping object-identifier to object-name.
    """
    manager = app.state.bacnet_manager
    local_addr = app.state.bacnet_proxy_local_address
    proxy_id = manager.ppm.get_proxy_id((local_addr, 0))
    peer = manager.ppm.peers.get(proxy_id)
    if not peer or not peer.socket_params:
        return JSONResponse(content={"status": "error", "error": "Proxy not registered or missing, cannot read object list names."})
    from protocol_proxy.ipc import ProtocolProxyMessage
    import json
    payload = {
        "device_address": device_address,
        "device_object_identifier": device_object_identifier
    }
    result = await manager.ppm.send(
        peer.socket_params,
        ProtocolProxyMessage(method_name="READ_OBJECT_LIST_NAMES",
                             payload=json.dumps(payload).encode('utf8'),
                             response_expected=True))
    if asyncio.isfuture(result):
        result = await result
    try:
        value = json.loads(result.decode('utf8'))
        return JSONResponse(content={"status": "done", "results": value})
    except Exception as e:
        return JSONResponse(content={"status": "error", "error": str(e)})