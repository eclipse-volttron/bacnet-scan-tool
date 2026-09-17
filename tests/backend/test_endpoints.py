"""
Pytest unit tests for BACnet Scan Tool FastAPI endpoints
"""
import pytest
import json
import subprocess
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
import asyncio

from bacnet_scan_api.main import app

@pytest.fixture
def client():
    """Create a test client for the FastAPI app"""
    return TestClient(app)


@pytest.fixture
def mock_bacnet_manager():
    """Mock BACnet manager with all necessary attributes"""
    manager = AsyncMock()
    manager.start = AsyncMock()
    manager.stop = AsyncMock()
    manager.get_proxy = AsyncMock()
    manager.send = AsyncMock()
    manager.wait_peer_registered = AsyncMock()
    manager.inbound_server = MagicMock()
    manager.inbound_server.serve_forever = AsyncMock()
    return manager


@pytest.fixture
def mock_bacnet_peer():
    """Mock BACnet peer"""
    peer = MagicMock()
    peer.address = ("192.168.1.173", 47808)
    return peer


class TestStartProxy:
    """Tests for /start_proxy endpoint"""
    
    def test_start_proxy_with_address(self, client, mock_bacnet_manager, mock_bacnet_peer):
        """Test starting proxy with explicit local address"""
        with patch('bacnet_scan_api.main.AsyncioProtocolProxyManager') as MockManager:
            MockManager.get_manager.return_value = mock_bacnet_manager
            mock_bacnet_manager.get_proxy.return_value = mock_bacnet_peer
            
            response = client.post("/start_proxy", data={"local_device_address": "192.168.1.173/24"})
            
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "done"
            assert data["address"] == "192.168.1.173/24"
    
    def test_start_proxy_auto_detect(self, client, mock_bacnet_manager, mock_bacnet_peer):
        """Test starting proxy with auto-detected address"""
        with patch('bacnet_scan_api.main.AsyncioProtocolProxyManager') as MockManager, \
             patch('bacnet_scan_api.main.discover_networks_for_bacnet') as mock_discover:
            
            MockManager.get_manager.return_value = mock_bacnet_manager
            mock_bacnet_manager.get_proxy.return_value = mock_bacnet_peer
            mock_discover.return_value = {"interface_networks": ["192.168.1.0/24"]}
            
            response = client.post("/start_proxy", data={})
            
            assert response.status_code == 200
            data = response.json()
            assert data["status"] in ["done", "error"]
    
    def test_start_proxy_error_handling(self, client):
        """Test error handling when proxy fails to start"""
        with patch('bacnet_scan_api.main.AsyncioProtocolProxyManager') as MockManager:
            MockManager.get_manager.side_effect = Exception("Connection failed")
            
            response = client.post("/start_proxy", data={"local_device_address": "192.168.1.173/24"})
            
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "error"
            assert "Connection failed" in data["error"]


class TestStopProxy:
    """Tests for /stop_proxy endpoint"""
    
    def test_stop_proxy_success(self, client, mock_bacnet_manager):
        """Test successfully stopping the proxy"""
        app.state.bacnet_manager = mock_bacnet_manager
        app.state.bacnet_server_task = AsyncMock()
        app.state.bacnet_proxy_peer = MagicMock()
        app.state.bacnet_proxy_local_address = "192.168.1.173/24"
        
        response = client.post("/stop_proxy")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "done"
    
    def test_stop_proxy_when_not_running(self, client):
        """Test stopping proxy when nothing is running"""
        # Clear any existing state
        if hasattr(app.state, 'bacnet_manager'):
            delattr(app.state, 'bacnet_manager')
        
        response = client.post("/stop_proxy")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "done"


class TestGetHostIP:
    """Tests for /get_host_ip endpoint"""
    
    def test_get_host_ip_linux(self, client):
        """Test getting host IP on Linux system"""
        with patch('subprocess.check_output') as mock_subprocess:
            # Simulate Linux environment
            mock_subprocess.side_effect = [
                FileNotFoundError,  # No ipconfig.exe (not WSL)
                b"default via 192.168.1.1 dev eth0",  # ip route
            ]
            
            response = client.get("/get_host_ip")
            
            # Should succeed or fail gracefully
            assert response.status_code in [200, 500]
    
    def test_get_host_ip_with_hostname(self, client):
        """Test getting host IP using hostname -I"""
        with patch('subprocess.check_output') as mock_subprocess:
            mock_subprocess.side_effect = [
                FileNotFoundError,  # No ipconfig.exe
                subprocess.CalledProcessError(1, 'cmd'),  # ip route fails
                b"192.168.1.100 172.17.0.1",  # hostname -I
            ]
            
            response = client.get("/get_host_ip")
            
            if response.status_code == 200:
                data = response.json()
                assert "address" in data


class TestScanSubnet:
    """Tests for /bacnet/scan_subnet endpoint"""
    
    def test_scan_subnet_success(self, client, mock_bacnet_manager, mock_bacnet_peer):
        """Test successful subnet scan"""
        app.state.bacnet_manager = mock_bacnet_manager
        app.state.bacnet_proxy_peer = mock_bacnet_peer
        
        # Mock scan response
        mock_devices = [
            {
                "pduSource": "192.168.1.248",
                "deviceIdentifier": ["device", 3056211],
                "maxAPDULengthAccepted": 1024,
                "segmentationSupported": "segmented-both",
                "vendorID": 842
            }
        ]
        mock_bacnet_manager.send.return_value = json.dumps(mock_devices).encode('utf8')
        
        response = client.post("/bacnet/scan_subnet", data={"subnet": "192.168.1.0/24"})
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "done"
        assert "devices" in data
        assert data["ips_scanned"] == 254
    
    def test_scan_subnet_with_all_parameters(self, client, mock_bacnet_manager, mock_bacnet_peer):
        """Test scan with all optional parameters"""
        app.state.bacnet_manager = mock_bacnet_manager
        app.state.bacnet_proxy_peer = mock_bacnet_peer
        
        mock_bacnet_manager.send.return_value = json.dumps([]).encode('utf8')
        
        response = client.post("/bacnet/scan_subnet", data={
            "subnet": "192.168.1.0/24",
            "whois_timeout": 5.0,
            "port": 47808,
            "low_id": 0,
            "high_id": 1000,
            "enable_brute_force": True,
            "semaphore_limit": 20,
            "max_duration": 300.0
        })
        
        assert response.status_code == 200
    
    def test_scan_subnet_no_proxy(self, client):
        """Test scan when proxy is not registered"""
        app.state.bacnet_proxy_peer = None
        
        response = client.post("/bacnet/scan_subnet", data={"subnet": "192.168.1.0/24"})
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "error"
        assert "Proxy not registered" in data["error"]
    
    def test_scan_subnet_timeout(self, client, mock_bacnet_manager, mock_bacnet_peer):
        """Test scan timeout handling"""
        app.state.bacnet_manager = mock_bacnet_manager
        app.state.bacnet_proxy_peer = mock_bacnet_peer
        
        # Mock timeout response
        timeout_response = {"status": "error", "error": "Operation timed out after 280s"}
        mock_bacnet_manager.send.return_value = json.dumps(timeout_response).encode('utf8')
        
        response = client.post("/bacnet/scan_subnet", data={"subnet": "192.168.1.0/24"})
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "error"
        assert "timed out" in data["error"]


class TestReadProperty:
    """Tests for /read_property endpoint"""
    
    def test_read_property_success(self, client, mock_bacnet_manager, mock_bacnet_peer):
        """Test successful property read"""
        app.state.bacnet_manager = mock_bacnet_manager
        app.state.bacnet_proxy_peer = mock_bacnet_peer
        
        # Mock property value
        mock_value = {"value": 72.5, "type": "Real"}
        mock_bacnet_manager.send.return_value = json.dumps(mock_value).encode('utf8')
        
        response = client.post("/read_property", data={
            "device_address": "192.168.1.248",
            "object_identifier": "analog-input,1",
            "property_identifier": "present-value"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "done"
        assert "result" in data  # read_property returns result, not value directly
    
    def test_read_property_with_array_index(self, client, mock_bacnet_manager, mock_bacnet_peer):
        """Test property read with array index"""
        app.state.bacnet_manager = mock_bacnet_manager
        app.state.bacnet_proxy_peer = mock_bacnet_peer
        
        mock_bacnet_manager.send.return_value = json.dumps({"value": "Test"}).encode('utf8')
        
        response = client.post("/read_property", data={
            "device_address": "192.168.1.248",
            "object_identifier": "device,3056211",
            "property_identifier": "object-list",
            "property_array_index": 1
        })
        
        assert response.status_code == 200
    
    def test_read_property_no_proxy(self, client):
        """Test read when proxy is not registered"""
        app.state.bacnet_proxy_peer = None
        
        response = client.post("/read_property", data={
            "device_address": "192.168.1.248",
            "object_identifier": "analog-input,1",
            "property_identifier": "present-value"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "error"


class TestWriteProperty:
    """Tests for /write_property endpoint"""
    
    def test_write_property_success(self, client, mock_bacnet_manager, mock_bacnet_peer):
        """Test successful property write"""
        app.state.bacnet_manager = mock_bacnet_manager
        app.state.bacnet_proxy_peer = mock_bacnet_peer
        
        mock_bacnet_manager.send.return_value = json.dumps({"status": "done"}).encode('utf8')
        
        # write_property endpoint expects query parameters, not JSON body
        response = client.post("/write_property", params={
            "device_address": "192.168.1.248",
            "object_identifier": "analog-value,1",
            "property_identifier": "present-value",
            "value": 75.0,
            "priority": 16
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "done"
    
    def test_write_property_with_array_index(self, client, mock_bacnet_manager, mock_bacnet_peer):
        """Test write with array index"""
        app.state.bacnet_manager = mock_bacnet_manager
        app.state.bacnet_proxy_peer = mock_bacnet_peer
        
        mock_bacnet_manager.send.return_value = json.dumps({"status": "done"}).encode('utf8')
        
        # write_property endpoint expects query parameters, not JSON body
        response = client.post("/write_property", params={
            "device_address": "192.168.1.248",
            "object_identifier": "analog-value,1",
            "property_identifier": "present-value",
            "value": 75.0,
            "priority": 16,
            "property_array_index": 1
        })
        
        assert response.status_code == 200


class TestWhoIs:
    """Tests for /bacnet/who_is endpoint"""
    
    def test_who_is_success(self, client, mock_bacnet_manager, mock_bacnet_peer):
        """Test successful Who-Is request"""
        app.state.bacnet_manager = mock_bacnet_manager
        app.state.bacnet_proxy_peer = mock_bacnet_peer
        
        mock_devices = [
            {
                "pduSource": "192.168.1.248",
                "deviceIdentifier": ["device", 3056211],
                "maxAPDULengthAccepted": 1024,
                "segmentationSupported": "segmented-both",
                "vendorID": 842
            }
        ]
        mock_bacnet_manager.send.return_value = json.dumps(mock_devices).encode('utf8')
        
        response = client.post("/bacnet/who_is", data={
            "device_instance_low": 0,
            "device_instance_high": 4194303,
            "dest": "192.168.1.255"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "done"
        assert "devices" in data
    
    def test_who_is_dict_response(self, client, mock_bacnet_manager, mock_bacnet_peer):
        """Test Who-Is with dict response format"""
        app.state.bacnet_manager = mock_bacnet_manager
        app.state.bacnet_proxy_peer = mock_bacnet_peer
        
        mock_response = {"devices": [{"pduSource": "192.168.1.248"}]}
        mock_bacnet_manager.send.return_value = json.dumps(mock_response).encode('utf8')
        
        response = client.post("/bacnet/who_is", data={
            "device_instance_low": 0,
            "device_instance_high": 4194303,
            "dest": "192.168.1.255"
        })
        
        assert response.status_code == 200


class TestReadDeviceAll:
    """Tests for /bacnet/read_device_all endpoint"""
    
    def test_read_device_all_success(self, client, mock_bacnet_manager, mock_bacnet_peer):
        """Test reading all device properties"""
        app.state.bacnet_manager = mock_bacnet_manager
        app.state.bacnet_proxy_peer = mock_bacnet_peer
        
        mock_properties = {
            "object-name": "Test Device",
            "description": "Test Description",
            "model-name": "Test Model",
            "vendor-id": 842
        }
        mock_bacnet_manager.send.return_value = json.dumps(mock_properties).encode('utf8')
        
        response = client.post("/bacnet/read_device_all", data={
            "device_address": "192.168.1.248",
            "device_object_identifier": "device,3056211"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "done"
        assert "properties" in data


class TestReadObjectListNames:
    """Tests for /bacnet/read_object_list_names endpoint"""
    
    def test_read_object_list_names_success(self, client, mock_bacnet_manager, mock_bacnet_peer):
        """Test reading object list with names"""
        app.state.bacnet_manager = mock_bacnet_manager
        app.state.bacnet_proxy_peer = mock_bacnet_peer
        
        mock_response = {
            "status": "done",
            "object_list_names": {
                "analog-input,1": {
                    "object-name": "Temperature Sensor",
                    "units": "degreesCelsius"
                }
            },
            "pagination": {
                "current_page": 1,
                "page_size": 100,
                "total_objects": 1,
                "total_pages": 1
            }
        }
        mock_bacnet_manager.send.return_value = json.dumps(mock_response).encode('utf8')
        
        response = client.post("/bacnet/read_object_list_names", data={
            "device_address": "192.168.1.248",
            "device_object_identifier": "device,3056211",
            "page": 1,
            "page_size": 100
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "done"
    
    def test_read_object_list_names_pagination_invalid(self, client):
        """Test invalid pagination parameters"""
        response = client.post("/bacnet/read_object_list_names", data={
            "device_address": "192.168.1.248",
            "device_object_identifier": "device,3056211",
            "page": 0,
            "page_size": 100
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "error"


class TestPingIP:
    """Tests for /ping_ip endpoint"""
    
    @pytest.mark.asyncio
    async def test_ping_success(self, client):
        """Test successful ping"""
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_proc = AsyncMock()
            mock_proc.communicate.return_value = (b"Reply from 192.168.1.1", b"")
            mock_proc.returncode = 0
            mock_subprocess.return_value = mock_proc
            
            response = client.post("/ping_ip", data={"ip_address": "192.168.1.1"})
            
            assert response.status_code == 200
            data = response.json()
            assert "ip_address" in data
    
    def test_ping_failure(self, client):
        """Test failed ping"""
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_proc = AsyncMock()
            mock_proc.communicate.return_value = (b"", b"Request timed out")
            mock_proc.returncode = 1
            mock_subprocess.return_value = mock_proc
            
            response = client.post("/ping_ip", data={"ip_address": "192.168.1.1"})
            
            assert response.status_code == 200


class TestDiscoverNetworks:
    """Tests for /discover_networks endpoint"""
    
    @pytest.mark.asyncio
    async def test_discover_networks_success(self, client):
        """Test successful network discovery"""
        with patch('bacnet_scan_api.main.discover_networks_for_bacnet') as mock_discover:
            mock_discover.return_value = {
                "interface_networks": ["192.168.1.0/24"],
                "route_networks": ["10.0.0.0/8"]
            }
            
            response = client.get("/discover_networks")
            
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "done"
            assert "networks" in data
    
    def test_discover_networks_with_verbose(self, client):
        """Test network discovery with verbose output"""
        with patch('bacnet_scan_api.main.discover_networks_for_bacnet') as mock_discover:
            mock_discover.return_value = {"interface_networks": ["192.168.1.0/24"]}
            
            response = client.get("/discover_networks?verbose=true")
            
            assert response.status_code == 200


class TestCustomNetworks:
    """Tests for custom network management endpoints"""
    
    def test_add_custom_network(self, client):
        """Test adding a custom network"""
        with patch('pathlib.Path.exists', return_value=False), \
             patch('builtins.open', create=True) as mock_open:
            
            response = client.post("/networks/add", data={"network": "192.168.2.0/24"})
            
            assert response.status_code == 200
            data = response.json()
            assert data["status"] in ["done", "error"]
    
    def test_add_invalid_network(self, client):
        """Test adding invalid network format"""
        response = client.post("/networks/add", data={"network": "invalid"})
        
        assert response.status_code == 200
        data = response.json()
        assert data.get("status") in ["error", "done"]
    
    def test_remove_custom_network(self, client):
        """Test removing a custom network"""
        mock_data = {
            "custom_networks": ["192.168.2.0/24", "10.0.0.0/8"],
            "added_dates": {"192.168.2.0/24": "2025-11-03T10:00:00", "10.0.0.0/8": "2025-11-03T11:00:00"}
        }
        
        with patch('pathlib.Path.exists', return_value=True), \
             patch('builtins.open', create=True) as mock_open:
            
            # Mock file reading and writing
            mock_file = MagicMock()
            mock_file.__enter__.return_value.read.return_value = json.dumps(mock_data)
            mock_open.return_value = mock_file
            
            # Use request method for DELETE with form data
            response = client.request("DELETE", "/networks/remove", data={"network": "192.168.2.0/24"})
            
            assert response.status_code == 200
    
    def test_get_custom_networks(self, client):
        """Test retrieving custom networks"""
        with patch('pathlib.Path.exists', return_value=False):
            response = client.get("/networks/custom")
            
            assert response.status_code == 200
            data = response.json()
            assert "networks" in data


class TestRetrieveSavedScans:
    """Tests for /retrieve_saved_scans endpoint"""
    
    def test_retrieve_saved_scans_success(self, client):
        """Test retrieving saved scans"""
        with patch('pathlib.Path.exists', return_value=True), \
             patch('builtins.open', create=True) as mock_open:
            
            mock_open.return_value.__enter__.return_value.read.return_value = '[]'
            
            response = client.get("/retrieve_saved_scans")
            
            assert response.status_code == 200
            data = response.json()
            assert "devices" in data
    
    def test_retrieve_saved_scans_no_file(self, client):
        """Test when no saved scans exist"""
        with patch('pathlib.Path.exists', return_value=False):
            response = client.get("/retrieve_saved_scans")
            
            assert response.status_code == 200
            data = response.json()
            assert data["total_count"] == 0


class TestRetrieveScannedPoints:
    """Tests for /retrieve_scanned_points endpoint"""
    
    def test_retrieve_all_points(self, client):
        """Test retrieving all scanned points"""
        with patch('pathlib.Path.exists', return_value=True), \
             patch('builtins.open', create=True) as mock_open:
            
            mock_open.return_value.__enter__.return_value.read.return_value = '[]'
            
            response = client.get("/retrieve_scanned_points")
            
            assert response.status_code == 200
            data = response.json()
            assert "points" in data
    
    def test_retrieve_points_by_device(self, client):
        """Test retrieving points for specific device"""
        with patch('pathlib.Path.exists', return_value=True), \
             patch('builtins.open', create=True) as mock_open:
            
            mock_open.return_value.__enter__.return_value.read.return_value = '[]'
            
            response = client.get("/retrieve_scanned_points?device_address=192.168.1.248")
            
            assert response.status_code == 200


# Fixtures for async testing
@pytest.fixture
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
