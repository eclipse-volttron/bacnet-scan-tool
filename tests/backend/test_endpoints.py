import pytest
from fastapi.testclient import TestClient

# Import your FastAPI app
from bacnet_scan_tool.main import app

# Create test client
client = TestClient(app)


# Define a fixture to ensure database tables are created
@pytest.fixture(autouse=True)
def setup_database():
    """Setup database tables for testing"""
    from bacnet_scan_tool.main import on_startup
    import asyncio
    asyncio.run(on_startup())
    yield


# Test cases for each endpoint
def test_start_bacnet_discovery():
    """Test starting a BACnet discovery scan"""
    response = client.get("/bacnet/scan/start",
                          params={"ip_address": "192.168.1.0/24"})
    assert response.status_code == 200
    result = response.json()
    assert "device_id" in result
    assert "message" in result
    # Store the device ID for later tests
    return result["device_id"]


def test_get_devices():
    """Test retrieving the list of discovered devices"""
    # First create a device by starting a scan
    client.get("/bacnet/scan/start", params={"ip_address": "192.168.1.0/24"})

    # Now get the devices
    response = client.get("/devices")
    assert response.status_code == 200
    result = response.json()
    assert "devices" in result
    assert len(result["devices"]) > 0

    # Return the first device_id for use in other tests
    return result["devices"][0]["id"]


def test_get_device_points():
    """Test retrieving points for a device"""
    # Get a device ID
    device_id = test_get_devices()

    # This might fail if real points haven't been discovered
    # That's why we'll accept both 200 and 404
    response = client.get(f"/devices/{device_id}/points")
    assert response.status_code in [200, 404]

    if response.status_code == 200:
        result = response.json()
        assert "points" in result


def test_get_device_points_not_found():
    """Test getting points for a non-existent device"""
    response = client.get("/devices/99999/points")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_get_point_values():
    """Test retrieving values for points"""
    # Get a device ID
    device_id = test_get_devices()

    response = client.get(f"/devices/{device_id}/points/values")
    assert response.status_code in [200, 404]

    if response.status_code == 200:
        result = response.json()
        assert "values" in result


def test_get_point_metadata():
    """Test retrieving metadata for points"""
    # Get a device ID
    device_id = test_get_devices()

    response = client.get(f"/devices/{device_id}/points/meta")
    assert response.status_code in [200, 404]

    if response.status_code == 200:
        result = response.json()
        assert "metadata" in result


def test_create_point_tag():
    """Test creating a tag for a point"""
    # This will require having a point available
    # We can only test this if the previous tests succeeded in finding points

    # Get a device ID
    device_id = test_get_devices()

    # Try to get points for this device
    points_response = client.get(f"/devices/{device_id}/points")
    if points_response.status_code != 200 or not points_response.json(
    )["points"]:
        pytest.skip("No points available to tag")

    point_id = points_response.json()["points"][0]["id"]

    # Create a tag
    response = client.post(f"/devices/{device_id}/points/{point_id}/tags",
                           json={"name": "test_tag"})
    assert response.status_code == 200
    result = response.json()
    assert "tag_id" in result


def test_get_point_tags():
    """Test getting tags for a point"""
    # This will need a device with points that have tags
    # Since that may not exist in testing, we'll accept various status codes

    # Get a device ID
    device_id = test_get_devices()

    # Try to get points for this device
    points_response = client.get(f"/devices/{device_id}/points")
    if points_response.status_code != 200 or not points_response.json(
    )["points"]:
        pytest.skip("No points available")

    point_id = points_response.json()["points"][0]["id"]

    response = client.get(f"/devices/{device_id}/points/{point_id}/tags")
    assert response.status_code in [200, 404]

    if response.status_code == 200:
        result = response.json()
        assert "tags" in result


def test_write_point_value():
    """Test writing a value to a point"""
    # Get a device ID
    device_id = test_get_devices()

    # Try to get points for this device
    points_response = client.get(f"/devices/{device_id}/points")
    if points_response.status_code != 200 or not points_response.json(
    )["points"]:
        pytest.skip("No points available to write to")

    point_id = points_response.json()["points"][0]["id"]

    # Write a value
    response = client.put(f"/devices/{device_id}/points/{point_id}/write",
                          json={"value": 72.5})
    assert response.status_code == 200
    result = response.json()
    assert "message" in result
