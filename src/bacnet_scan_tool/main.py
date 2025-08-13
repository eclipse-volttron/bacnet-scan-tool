import asyncio
import json
import socket
from typing import Optional, Any

from fastapi import FastAPI, HTTPException, Form, Query

from protocol_proxy.ipc import ProtocolProxyMessage, ProtocolProxyPeer
from protocol_proxy.manager.asyncio import AsyncioProtocolProxyManager
from protocol_proxy.protocol.bacnet import BACnetProxy

from .models import (
    IPAddress, LocalIPResponse, ProxyResponse, ScanResponse,
    PropertyReadResponse, DevicePropertiesResponse, WhoIsResponse, PingResponse,
    ObjectListNamesResponse, PaginationInfo, ObjectProperties,
    SavedDevice, ScannedPoint, SavedScansResponse, ScannedPointsResponse
)

app = FastAPI()


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
        if hasattr(app.state, "bacnet_manager") and app.state.bacnet_manager:
            await app.state.bacnet_manager.stop()
            if hasattr(app.state, "bacnet_server_task") and app.state.bacnet_server_task:
                app.state.bacnet_server_task.cancel()
            await asyncio.sleep(0.5)
        
        app.state.bacnet_manager = AsyncioProtocolProxyManager.get_manager(BACnetProxy)
        await app.state.bacnet_manager.start()
        
        app.state.bacnet_server_task = asyncio.create_task(app.state.bacnet_manager.inbound_server.serve_forever())
        
        app.state.bacnet_proxy_peer = await app.state.bacnet_manager.get_proxy(
            (local_device_address, 0), 
            local_device_address=local_device_address
        )
        app.state.bacnet_proxy_local_address = local_device_address
        
        asyncio.create_task(app.state.bacnet_manager.wait_peer_registered(
            peer=app.state.bacnet_proxy_peer, 
            timeout=5
        ))
        await asyncio.sleep(1)
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
        pass
    
    try:
        try:
            route_output = subprocess.check_output(
                ["ip", "route", "show", "default"], 
                encoding="utf-8"
            )
            import re
            match = re.search(r'dev\s+(\S+)', route_output)
            if match:
                interface = match.group(1)
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
        
        try:
            with open('/proc/net/route', 'r') as f:
                for line in f:
                    fields = line.strip().split()
                    if len(fields) >= 2 and fields[1] == '00000000':
                        interface = fields[0]
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
        
        raise HTTPException(status_code=500, detail="Could not determine host IPv4 address on this system.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not determine host IPv4 address: {str(e)}")


@app.post("/bacnet/scan_subnet", response_model=ScanResponse)
async def scan_subnet(
    subnet: str = Form(...),
    whois_timeout: Optional[float] = Form(None),
    port: Optional[int] = Form(None),
    low_id: Optional[int] = Form(None),
    high_id: Optional[int] = Form(None),
    enable_brute_force: Optional[bool] = Form(None),
    semaphore_limit: Optional[int] = Form(None),
    max_duration: Optional[float] = Form(None),
    force_fresh_scan: Optional[bool] = Form(False)
):
    """
    Scan a subnet (CIDR notation, e.g. 192.168.1.0/24) for BACnet devices using hybrid Who-Is.
    All parameters except subnet are optional and will use backend defaults if not provided.
    
    Parameters:
    - subnet: Network in CIDR notation (required)
    - whois_timeout: Timeout for Who-Is broadcasts (default: 3.0s)
    - port: BACnet port (default: 47808)
    - low_id/high_id: Device instance range (default: 0-4194303)
    - enable_brute_force: Enable unicast sweep fallback (default: True)
    - semaphore_limit: Concurrency limit (default: 20)
    - max_duration: Maximum scan duration (default: 280s)
    - force_fresh_scan: Skip cache and force fresh scan (default: False)
    """
    manager = app.state.bacnet_manager
    peer = app.state.bacnet_proxy_peer
    if not peer:
        import ipaddress
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            ips_scanned = net.num_addresses - 2 if net.num_addresses > 2 else net.num_addresses
        except Exception:
            ips_scanned = 0
        return ScanResponse(
            status="error",
            error="Proxy not registered, cannot scan.",
            ips_scanned=ips_scanned
        )
    from protocol_proxy.ipc import ProtocolProxyMessage
    import json
    
    # Build payload with only non-None/non-empty values
    payload = {"network": subnet}
    
    # Handle optional parameters, filtering out None, empty strings, and 0 values where appropriate
    if whois_timeout is not None and whois_timeout > 0:
        payload["whois_timeout"] = whois_timeout
    if port is not None and port > 0:
        payload["port"] = port
    if low_id is not None and low_id >= 0:
        payload["low_id"] = low_id
    if high_id is not None and high_id >= 0:
        payload["high_id"] = high_id
    if enable_brute_force is not None:
        payload["enable_brute_force"] = enable_brute_force
    if semaphore_limit is not None and semaphore_limit > 0:
        payload["semaphore_limit"] = semaphore_limit
    if max_duration is not None and max_duration > 0:
        payload["max_duration"] = max_duration
    if force_fresh_scan is not None:
        payload["force_fresh_scan"] = force_fresh_scan
    import ipaddress
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        ips_scanned = net.num_addresses - 2 if net.num_addresses > 2 else net.num_addresses
    except Exception:
        ips_scanned = 0
    result = await manager.send(
        peer,
        ProtocolProxyMessage(method_name="SCAN_SUBNET",
                             payload=json.dumps(payload).encode('utf8'),
                             response_expected=True))
    if asyncio.isfuture(result):
        result = await result
    try:
        value = json.loads(result.decode('utf8'))

        if isinstance(value, dict) and value.get(
                'status') == 'error' and 'timed out' in value.get('error', ''):
            return ScanResponse(
                status="error",
                error=f"Scan operation timed out: {value.get('error', 'Unknown timeout error')}",
                ips_scanned=ips_scanned
            )

        from .models import BACnetDevice
        processed = []
        for dev in value:
            dev_out = {}
            for k in ["pduSource", "deviceIdentifier", "maxAPDULengthAccepted", "segmentationSupported", "vendorID"]:
                if k in dev:
                    dev_out[k] = dev[k]
            did = dev_out.get("deviceIdentifier")
            if isinstance(did, (list, tuple)) and len(did) == 2:
                dev_out["device_instance"] = did[1]
                dev_out["deviceIdentifier"] = f"{did[0]},{did[1]}"
            pdu_source = dev.get("pduSource")
            if isinstance(pdu_source, str):
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
        return str(obj.name)
    if hasattr(
            obj,
            '__class__') and obj.__class__.__name__.startswith('ObjectType'):
        return str(obj)
    if isinstance(obj, ipaddress.IPv4Address) or isinstance(
            obj, ipaddress.IPv6Address):
        return str(obj)
    return str(obj)


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
    manager = app.state.bacnet_manager
    peer = app.state.bacnet_proxy_peer
    if not peer:
        raise HTTPException(status_code=400, detail="Proxy not registered")
    
    message = ProtocolProxyMessage(method_name="WRITE_PROPERTY",
                                   payload=json.dumps({
                                       "device_address": device_address,
                                       "object_identifier": object_identifier,
                                       "property_identifier": property_identifier,
                                       "value": value,
                                       "priority": priority,
                                       "property_array_index": property_array_index
                                   }).encode('utf8'),
                                   response_expected=True)

    send_result = await manager.send(peer, message)
    print("Sent WRITE_PROPERTY message")
    # If the result is a Future, await it
    import asyncio
    if asyncio.isfuture(send_result):
        send_result = await send_result
    # If bytes, try to decode and parse JSON
    if isinstance(send_result, bytes):
        try:
            result_json = json.loads(send_result.decode('utf8'))
            from .main import make_jsonable
            return {"status": "done", "result": make_jsonable(result_json)}
        except Exception as e:
            return {"status": "error", "error": f"Could not decode response: {e}"}
    # If dict, str, or other, ensure JSON serializable
    from .main import make_jsonable
    return {"status": "done", "result": make_jsonable(send_result)}


@app.post("/read_property", response_model=PropertyReadResponse)
async def read_property(device_address: str = Form(...),
                        object_identifier: str = Form(...),
                        property_identifier: str = Form(...),
                        property_array_index: Optional[int] = Form(None)):
    """
    Perform a BACnet property read and return the result directly (waits for completion).
    """
    print(
        "[read_property] Using global AsyncioProtocolProxyManager from app.state...")
    try:
        manager = app.state.bacnet_manager
        peer = app.state.bacnet_proxy_peer
        if not peer:
            print(
                "[read_property] Proxy not registered!"
            )
            return PropertyReadResponse(
                status="error",
                error="Proxy not registered, cannot send request."
            )
        payload = {
            'device_address': device_address,
            'object_identifier': object_identifier,
            'property_identifier': property_identifier
        }
        if property_array_index is not None:
            payload['property_array_index'] = property_array_index
        print(f"[read_property] Sending ProtocolProxyMessage: {payload}")

        result = await manager.send(
            peer,
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
            normalized = value
            if property_identifier.lower().replace("-", "_") == "object_name":
                if isinstance(value, dict):
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
    peer = app.state.bacnet_proxy_peer
    if not peer:
        return DevicePropertiesResponse(
            status="error",
            error="Proxy not registered, cannot read device."
        )
    from protocol_proxy.ipc import ProtocolProxyMessage
    import json
    payload = {
        "device_address": device_address,
        "device_object_identifier": device_object_identifier
    }
    result = await manager.send(
        peer,
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


@app.post("/bacnet/who_is", response_model=WhoIsResponse)
async def who_is(device_instance_low: int = Form(...),
                 device_instance_high: int = Form(...),
                 dest: str = Form(...)):
    """
    Send a Who-Is request to a BACnet address or range.
    """
    manager = app.state.bacnet_manager
    peer = app.state.bacnet_proxy_peer
    if not peer:
        return WhoIsResponse(
            status="error",
            error="Proxy not registered, cannot send Who-Is."
        )
    from protocol_proxy.ipc import ProtocolProxyMessage
    import json
    payload = {
        "device_instance_low": device_instance_low,
        "device_instance_high": device_instance_high,
        "dest": dest
    }
    result = await manager.send(
        peer,
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


device_points = {}
point_tags = {}


@app.post("/ping_ip", response_model=PingResponse)
async def ping_ip(ip_address: str = Form(...)):
    """
    Ping the given IP address and return the result. Waits for a response, shows loading in UI until done.
    """
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


from fastapi.responses import JSONResponse
@app.post("/bacnet/read_object_list_names", response_model=ObjectListNamesResponse)
async def read_object_list_names(
    device_address: str = Form(...), 
    device_object_identifier: str = Form(...),
    page: int = Form(1),
    page_size: int = Form(100),
    force_fresh_read: bool = Form(False)
):
    """
    Reads the object-list from a device, then reads object-name and units for each object in the list.
    Returns a paginated dict mapping object-identifier to ObjectInfo (containing object-name and units).
    
    Args:
        device_address: BACnet device address
        device_object_identifier: Device object identifier
        page: Page number (1-based)
        page_size: Number of objects per page (default 100)
        force_fresh_read: If True, bypass cache and read fresh from device (default False)
    """
    # Validate pagination parameters
    if page < 1:
        return ObjectListNamesResponse(status="error", error="Page number must be 1 or greater")
    if page_size < 1 or page_size > 1000:
        return ObjectListNamesResponse(status="error", error="Page size must be between 1 and 1000")
    
    manager = app.state.bacnet_manager
    peer = app.state.bacnet_proxy_peer
    if not peer:
        return ObjectListNamesResponse(status="error", error="Proxy not registered, cannot read object list names.")
    from protocol_proxy.ipc import ProtocolProxyMessage
    import json
    payload = {
        "device_address": device_address,
        "device_object_identifier": device_object_identifier,
        "page": page,
        "page_size": page_size,
        "force_fresh_read": force_fresh_read
    }
    
    try:
        result = await asyncio.wait_for(
            manager.send(
                peer,
                ProtocolProxyMessage(method_name="READ_OBJECT_LIST_NAMES",
                                   payload=json.dumps(payload).encode('utf8'),
                                   response_expected=True)
            ),
            timeout=120
        )
        
        if asyncio.isfuture(result):
            result = await result
            
        response = json.loads(result.decode('utf8'))
        
        if response.get('status') == 'done':
            pagination_data = response.get('pagination', {})
            pagination = PaginationInfo(
                page=pagination_data.get('page', page),
                page_size=pagination_data.get('page_size', page_size),
                total_items=pagination_data.get('total_items', 0),
                total_pages=pagination_data.get('total_pages', 0),
                has_next=pagination_data.get('has_next', False),
                has_previous=pagination_data.get('has_previous', False)
            )
            
            raw_results = response.get('results', {})
            processed_results = {}
            
            for obj_id, properties in raw_results.items():
                if isinstance(properties, dict):
                    units_value = properties.get('units')
                    if units_value is not None:
                        units_str = str(units_value)
                    else:
                        units_str = None
                    
                    present_value = properties.get('present-value')
                    if present_value is not None:
                        present_value_str = str(present_value)
                    else:
                        present_value_str = None
                    
                    processed_results[obj_id] = ObjectProperties(
                        object_name=properties.get('object-name'),
                        units=units_str,
                        present_value=present_value_str
                    )
                else:
                    processed_results[obj_id] = ObjectProperties(
                        object_name=str(properties),
                        units=None,
                        present_value=None
                    )
            
            return ObjectListNamesResponse(
                status="done",
                results=processed_results,
                pagination=pagination
            )
        else:
            return ObjectListNamesResponse(
                status="error",
                error=response.get('error', 'Unknown error occurred')
            )
        
    except asyncio.TimeoutError:
        return ObjectListNamesResponse(status="error", error="Request timed out after 2 minutes")
    except Exception as e:
        return ObjectListNamesResponse(status="error", error=str(e))
    
@app.post("/stop_proxy", response_model=ProxyResponse)
async def stop_proxy():
    """
    Stop the running BACnet proxy and clean up state.
    """
    try:
        if hasattr(app.state, "bacnet_manager") and app.state.bacnet_manager:
            await app.state.bacnet_manager.stop()
            if hasattr(app.state, "bacnet_server_task") and app.state.bacnet_server_task:
                app.state.bacnet_server_task.cancel()
            await asyncio.sleep(0.5)
            app.state.bacnet_manager = None
        if hasattr(app.state, "bacnet_server_task"):
            app.state.bacnet_server_task = None
        if hasattr(app.state, "bacnet_proxy_peer"):
            app.state.bacnet_proxy_peer = None
        if hasattr(app.state, "bacnet_proxy_local_address"):
            app.state.bacnet_proxy_local_address = None
        return ProxyResponse(status="done", message="BACnet proxy stopped.")
    except Exception as e:
        return ProxyResponse(status="error", error=str(e))


@app.get("/retrieve_saved_scans", response_model=SavedScansResponse)
async def retrieve_saved_scans():
    """
    Retrieve all discovered devices from the JSON cache file.
    Returns the complete list of scanned devices.
    """
    try:
        from pathlib import Path
        cache_dir = Path.home() / '.bacnet_scan_tool'
        json_file = cache_dir / 'discovered_devices.json'
        
        if not json_file.exists():
            return {
                "status": "error",
                "error": "No saved scans found. Run a subnet scan first.",
                "devices": [],
                "total_count": 0
            }
        
        with open(json_file, 'r') as f:
            devices = json.load(f)
        
        return {
            "status": "done",
            "devices": devices,
            "total_count": len(devices)
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error": f"Error loading saved scans: {str(e)}",
            "devices": [],
            "total_count": 0
        }


@app.get("/retrieve_scanned_points", response_model=ScannedPointsResponse)
async def retrieve_scanned_points(device_address: Optional[str] = Query(None)):
    """
    Retrieve object properties from the JSON cache file.
    
    Args:
        device_address: Optional IP address to filter points for a specific device.
                       If not provided, returns all scanned points.
    """
    try:
        from pathlib import Path
        cache_dir = Path.home() / '.bacnet_scan_tool'
        json_file = cache_dir / 'object_properties.json'
        
        if not json_file.exists():
            return {
                "status": "error", 
                "error": "No scanned points found. Read some device objects first.",
                "points": [],
                "total_count": 0
            }
        
        with open(json_file, 'r') as f:
            all_points = json.load(f)
        
        # Filter by device address if provided
        if device_address:
            filtered_points = [
                point for point in all_points 
                if point.get('device_address') == device_address
            ]
            return {
                "status": "done",
                "points": filtered_points,
                "total_count": len(filtered_points),
                "filtered_by": device_address
            }
        else:
            return {
                "status": "done",
                "points": all_points,
                "total_count": len(all_points)
            }
        
    except Exception as e:
        return {
            "status": "error",
            "error": f"Error loading scanned points: {str(e)}",
            "points": [],
            "total_count": 0
        }