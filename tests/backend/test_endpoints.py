import pytest
from fastapi.testclient import TestClient

# Import your FastAPI app
from bacnet_scan_tool.main import app

# Create test client
client = TestClient(app)

# API endpoint constants
TOOL_NAME = "bacnet"
SCAN_ENDPOINT = f"/{TOOL_NAME}/scan/start"
DEVICES_ENDPOINT = "/devices"
POINTS_ENDPOINT = "/points"
VALUES_ENDPOINT = "/points/values"
META_ENDPOINT = "/points/meta"
TAGS_ENDPOINT = "/tags"
WRITE_ENDPOINT = "/write"

# Test data constants
TEST_IP_RANGE = "192.168.1.0/24"


@pytest.fixture
def run_fake_scan():
    """Run a fake scan to populate data structures with test data"""
    response = client.get(SCAN_ENDPOINT,
                          params={
                              "ip_address": TEST_IP_RANGE,
                              "fake": "true"
                          })
    assert response.status_code == 200
    assert "device_id" in response.json()
    return response.json()["device_id"]


def test_start_bacnet_discovery():
    """Test starting a BACnet scan"""
    response = client.get(SCAN_ENDPOINT,
                          params={
                              "ip_address": TEST_IP_RANGE,
                              "fake": "true"
                          })
    assert response.status_code == 200
    result = response.json()
    assert "device_id" in result
    assert "message" in result


def test_get_devices(run_fake_scan):
    """Test retrieving devices after a scan"""
    response = client.get(DEVICES_ENDPOINT)
    assert response.status_code == 200
    result = response.json()
    assert "devices" in result
    assert len(result["devices"]) > 0
    # Check for expected device fields
    device = result["devices"][0]
    assert "id" in device
    assert "ip_address" in device


def test_get_device_points(run_fake_scan):
    """Test retrieving points for a specific device"""
    device_id = run_fake_scan
    response = client.get(f"{DEVICES_ENDPOINT}/{device_id}{POINTS_ENDPOINT}")
    assert response.status_code == 200
    result = response.json()
    assert "points" in result
    assert len(result["points"]) > 0
    # Check for expected point fields
    point = result["points"][0]
    assert "id" in point
    assert "name" in point
    assert "device_id" in point


def test_get_point_values(run_fake_scan):
    """Test retrieving values for all points of a device"""
    device_id = run_fake_scan
    response = client.get(f"{DEVICES_ENDPOINT}/{device_id}{VALUES_ENDPOINT}")
    assert response.status_code == 200
    result = response.json()
    assert "values" in result
    # Values should be a dictionary with point_id keys
    assert len(result["values"]) > 0
    # Get first point_id and value
    point_id = list(result["values"].keys())[0]
    point_data = result["values"][point_id]
    assert "value" in point_data


def test_get_point_metadata(run_fake_scan):
    """Test retrieving metadata for all points of a device"""
    device_id = run_fake_scan
    response = client.get(f"{DEVICES_ENDPOINT}/{device_id}{META_ENDPOINT}")
    assert response.status_code == 200
    result = response.json()
    assert "metadata" in result
    # Metadata should be a dictionary with point_id keys
    assert len(result["metadata"]) > 0


def test_create_point_tag(run_fake_scan):
    """Test creating a tag for a specific point"""
    device_id = run_fake_scan
    # Get a point ID first
    points_response = client.get(
        f"{DEVICES_ENDPOINT}/{device_id}{POINTS_ENDPOINT}")
    assert points_response.status_code == 200
    point_id = points_response.json()["points"][0]["id"]

    # Create a tag
    tag_data = {"name": "test_tag"}
    response = client.post(
        f"{DEVICES_ENDPOINT}/{device_id}/points/{point_id}{TAGS_ENDPOINT}",
        json=tag_data)
    assert response.status_code == 200
    result = response.json()
    assert "tag_id" in result
    assert "message" in result


def test_get_point_tags(run_fake_scan):
    """Test retrieving tags for a specific point"""
    device_id = run_fake_scan
    # Get a point ID first
    points_response = client.get(
        f"{DEVICES_ENDPOINT}/{device_id}{POINTS_ENDPOINT}")
    assert points_response.status_code == 200
    point_id = points_response.json()["points"][0]["id"]

    # First add a tag
    tag_data = {"name": "test_tag"}
    client.post(
        f"{DEVICES_ENDPOINT}/{device_id}/points/{point_id}{TAGS_ENDPOINT}",
        json=tag_data)

    # Get the tags
    response = client.get(
        f"{DEVICES_ENDPOINT}/{device_id}/points/{point_id}{TAGS_ENDPOINT}")
    assert response.status_code == 200
    result = response.json()
    assert "tags" in result
    assert "test_tag" in result["tags"]


def test_write_point_value(run_fake_scan):
    """Test writing a value to a specific point"""
    device_id = run_fake_scan
    # Get a point ID first
    points_response = client.get(
        f"{DEVICES_ENDPOINT}/{device_id}{POINTS_ENDPOINT}")
    assert points_response.status_code == 200
    point_id = points_response.json()["points"][0]["id"]

    # Write a value to the point
    write_data = {"value": 72.5}
    response = client.put(
        f"{DEVICES_ENDPOINT}/{device_id}/points/{point_id}{WRITE_ENDPOINT}",
        json=write_data)
    assert response.status_code == 200
    result = response.json()
    assert "message" in result


def test_nonexistent_device():
    """Test accessing a device that doesn't exist"""
    response = client.get(f"{DEVICES_ENDPOINT}/99999{POINTS_ENDPOINT}")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_invalid_tool_name():
    """Test using an invalid tool name"""
    response = client.get("/invalid-tool/scan/start",
                          params={"ip_address": TEST_IP_RANGE})
    assert response.status_code == 400
    assert "unsupported tool" in response.json()["detail"].lower()
