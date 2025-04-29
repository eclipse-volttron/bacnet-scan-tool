import pytest
from fastapi.testclient import TestClient

# Import the FastAPI app directly, similar to the volttron-installer test
from bacnet_scan_tool.main import app

# Create test client (notice there's no .api attribute unlike volttron-installer)
client = TestClient(app)

# Define API endpoint constants
TOOL_NAME = "bacnet"
SCAN_ENDPOINT = f"/{TOOL_NAME}/scan/start"
DEVICES_ENDPOINT = "/devices"
POINTS_ENDPOINT = "/points"
VALUES_ENDPOINT = "/points/values"
META_ENDPOINT = "/points/meta"
TAGS_ENDPOINT = "/tags"
WRITE_ENDPOINT = "/write"

# Test data
TEST_IP_RANGE = "192.168.1.0/24"


@pytest.fixture
def setup_device():
    """Create a device entry for testing"""
    response = client.get(SCAN_ENDPOINT, params={"ip_address": TEST_IP_RANGE})
    assert response.status_code == 200
    return response.json()["device_id"]


def test_start_bacnet_discovery():
    """Test starting a BACnet discovery scan"""
    response = client.get(SCAN_ENDPOINT, params={"ip_address": TEST_IP_RANGE})
    assert response.status_code == 200
    result = response.json()
    assert "device_id" in result
    assert "message" in result


def test_get_devices(setup_device):
    """Test retrieving the list of discovered devices"""
    response = client.get(DEVICES_ENDPOINT)
    assert response.status_code == 200
    result = response.json()
    assert "devices" in result
    assert len(result["devices"]) > 0


def test_get_device_points(setup_device):
    """Test retrieving points for a device"""
    device_id = setup_device
    response = client.get(f"{DEVICES_ENDPOINT}/{device_id}{POINTS_ENDPOINT}")
    assert response.status_code == 200
    result = response.json()
    assert "points" in result


def test_get_device_points_not_found():
    """Test getting points for a non-existent device"""
    response = client.get(f"{DEVICES_ENDPOINT}/99999{POINTS_ENDPOINT}")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_get_point_values(setup_device):
    """Test retrieving values for points"""
    device_id = setup_device
    response = client.get(f"{DEVICES_ENDPOINT}/{device_id}{VALUES_ENDPOINT}")
    assert response.status_code == 200
    result = response.json()
    assert "values" in result


def test_get_point_metadata(setup_device):
    """Test retrieving metadata for points"""
    device_id = setup_device
    response = client.get(f"{DEVICES_ENDPOINT}/{device_id}{META_ENDPOINT}")
    assert response.status_code == 200
    result = response.json()
    assert "metadata" in result


def test_create_and_get_point_tags(setup_device):
    """Test creating and then retrieving tags for a point"""
    device_id = setup_device

    # First get points to find a valid point_id
    points_response = client.get(
        f"{DEVICES_ENDPOINT}/{device_id}{POINTS_ENDPOINT}")
    assert points_response.status_code == 200
    point_id = points_response.json()["points"][0]["id"]

    # Create a tag
    tag_data = {"name": "test_tag"}
    create_response = client.post(
        f"{DEVICES_ENDPOINT}/{device_id}/points/{point_id}{TAGS_ENDPOINT}",
        json=tag_data)
    assert create_response.status_code == 200
    assert "tag_id" in create_response.json()

    # Get tags
    get_response = client.get(
        f"{DEVICES_ENDPOINT}/{device_id}/points/{point_id}{TAGS_ENDPOINT}")
    assert get_response.status_code == 200
    assert "tags" in get_response.json()


def test_write_point_value(setup_device):
    """Test writing a value to a point"""
    device_id = setup_device

    # First get points to find a valid point_id
    points_response = client.get(
        f"{DEVICES_ENDPOINT}/{device_id}{POINTS_ENDPOINT}")
    assert points_response.status_code == 200
    point_id = points_response.json()["points"][0]["id"]

    # Write a value
    write_data = {"value": 72.5}
    response = client.put(
        f"{DEVICES_ENDPOINT}/{device_id}/points/{point_id}{WRITE_ENDPOINT}",
        json=write_data)
    assert response.status_code == 200
    assert "message" in response.json()
