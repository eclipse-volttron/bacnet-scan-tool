# BACnet Scan Tool API

## About

The BACnet Scan Tool is a FastAPI-based web service that provides a comprehensive interface for discovering, communicating with, and managing BACnet devices on your network. This tool acts as a bridge between web applications and BACnet networks, offering both REST API endpoints and an interactive web interface for BACnet operations.

### Key Features

- **Device Discovery**: Scan IP ranges to automatically discover BACnet devices using Who-Is requests
- **Property Operations**: Read and write BACnet device properties with full support for array indices and priority levels
- **Network Intelligence**: Automatically detect local network interfaces and provide guidance for optimal scanning
- **Cross-Platform Support**: Works on Linux, Windows, and WSL2 environments with automatic network configuration
- **Interactive API**: Built-in Swagger UI for easy testing and exploration of all endpoints

### Use Cases

- **Building Automation Integration**: Connect web applications to BACnet building systems
- **Network Commissioning**: Discover and verify BACnet devices during installation
- **System Monitoring**: Read device properties for monitoring and reporting applications
- **Device Configuration**: Write properties to configure BACnet devices remotely
- **Network Troubleshooting**: Identify and diagnose BACnet communication issues

This tool is particularly useful for developers building web-based building automation systems, facility managers needing to monitor BACnet networks, and system integrators working with BACnet devices.

## Build

To build the `bacnet-scan-tool`, ensure you have Python 3.10 or higher installed, then run the following commands:

```bash
# Clone the repository
git clone https://github.com/your-repo/bacnet-scan-tool.git
cd bacnet-scan-tool
```

## Install Poetry

This project uses [Poetry](https://python-poetry.org/) for dependency management. To install Poetry, run:

```bash
# Using the official installation script
curl -sSL https://install.python-poetry.org | python3 -

# Add Poetry to your PATH (if not already added)
export PATH="$HOME/.local/bin:$PATH"
```

Verify the installation:

```bash
poetry --version
```

## Setup Virtual Environment

Once Poetry is installed, set up the virtual environment and install dependencies:

```bash
# Install dependencies
poetry install
```

## Usage

### Start the FastAPI Web Server

Start the server with Poetry:

```bash
poetry run uvicorn bacnet_scan_tool.main:app --reload
```

The server will be available at [http://127.0.0.1:8000](http://127.0.0.1:8000).
Access the UI here: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)



## BACnet Scan Tool – Usage Guide & API Workflow

### Recommended Flow

1. **Start the BACnet Proxy**
   - **POST /start_proxy**
     - Call with no parameters to auto-select your machine’s main outbound IP (recommended for most users).
     - Advanced: Provide `local_device_address` to bind to a specific local IP/interface.
     - **Returns:**
       ```json
       { "status": "done", "address": "192.168.1.100" }
       ```
       On error:
       ```json
       { "status": "error", "error": "Proxy not registered or missing socket_params." }
       ```

2. **(Optional) Check Your Local IP**
   - **GET /get_local_ip**
     - Returns the local IP, subnet mask, and CIDR for the interface used to reach a target IP (default is 8.8.8.8).
     - **Returns:**
       ```json
       { "local_ip": "192.168.1.100", "subnet_mask": "255.255.255.0", "cidr": "192.168.1.100/24" }
       ```
       On error:
       ```json
       { "local_ip": "127.0.0.1", "error": "Could not determine local IP." }
       ```

3. **(Optional, for WSL2 Users) Get Windows Host IP**
   - **GET /get_windows_host_ip**
     - Returns the first non-loopback IPv4 address from the Windows host (helpful for WSL2 environments).
     - **Returns:**
       ```json
       { "windows_host_ip": "192.168.1.50" }
       ```
     - **Tip:** Use this if you know your BACnet device is on the same network as your Windows host. You can use the returned IP to determine the correct subnet for scanning.

4. **Scan for BACnet Devices**
   - **POST /bacnet/scan_ip_range**
     - **Form Data:** `network_str` (CIDR, e.g., `192.168.1.0/24`)
     - **Description:** Scans the given IP range for BACnet devices and returns a list of discovered devices with their identifiers and object names.
     - **Returns (success):**
       ```json
       {
         "status": "done",
         "devices": [
           {
             "pduSource": "192.168.1.101",
             "deviceIdentifier": "8,123456",
             "maxAPDULengthAccepted": 1024,
             "segmentationSupported": "segmented-both",
             "vendorID": 5,
             "object-name": "Device-A",
             "scanned_ip_target": "192.168.1.101",
             "device_instance": 123456
           },
           {
             "pduSource": "192.168.1.102",
             "deviceIdentifier": "8,789012",
             "maxAPDULengthAccepted": 1024,
             "segmentationSupported": "segmented-both",
             "vendorID": 5,
             "object-name": "Device-B",
             "scanned_ip_target": "192.168.1.102",
             "device_instance": 789012
           }
         ]
       }
       ```
       If no devices found:
       ```json
       { "status": "done", "devices": [] }
       ```
       On error:
       ```json
       { "status": "error", "error": "Proxy not registered or missing, cannot scan." }
       ```
     - **Tip:** If you are unsure of your network range, use `/get_local_ip` or `/get_windows_host_ip` to help determine the correct subnet.

5. **Read or Write Properties**
   - **POST /read_property**
     - **Form Data:** `device_address`, `object_identifier`, `property_identifier`, `property_array_index` (optional)
     - **Returns:** Value of the property.
   - **POST /write_property**
     - **Form Data:** `device_address`, `object_identifier`, `property_identifier`, `value`, `priority`, `property_array_index` (optional)
     - **Returns:** Result of the write operation.
   - **Note:** `property_array_index` is only needed for array properties—leave blank for most reads/writes.

6. **Stop the Proxy**
   - **POST /stop_proxy**
     - Stops the running BACnet proxy and cleans up state.
     - **Returns:** Status message.

---

### Flow Summary

1. Start the proxy (auto-selects the best local IP by default)
2. (Optional) Check your local or Windows host IP
3. Scan for devices on your network
4. Read/write properties as needed
5. Stop the proxy when done

---

### API Endpoints

#### 1. Start BACnet Proxy
- **POST /start_proxy**
  - **Description:** Start the BACnet proxy with the given local device address (IP).
  - **Form Data:**
    - `local_device_address`: Local IP address to bind the proxy.
  - **Returns:** Status and address.

#### 2. Stop BACnet Proxy
- **POST /stop_proxy**
  - **Description:** Stop the running BACnet proxy and clean up state.
  - **Returns:** Status message.

#### 3. Write Property
- **POST /write_property**
  - **Description:** Write a value to a specific property of a BACnet device.
  - **Form Data:**
    - `device_address`, `object_identifier`, `property_identifier`, `value`, `priority`, `property_array_index` (optional)
  - **Returns:** Result of the write operation.

#### 4. Read Property
- **POST /read_property**
  - **Description:** Read a property from a BACnet device.
  - **Form Data:**
    - `device_address`, `object_identifier`, `property_identifier`, `property_array_index` (optional)
  - **Returns:** Value of the property.

#### 5. Ping IP
- **POST /ping_ip**
  - **Description:** Ping an IP address and return the result.
  - **Form Data:**
    - `ip_address`: IP address to ping.
  - **Returns:** Success status and ping output.

#### 6. Scan IP Range for BACnet Devices
- **POST /bacnet/scan_ip_range**
  - **Description:** Scan a range of IPs for BACnet devices using Who-Is.
  - **Form Data:**
    - `network_str`: Subnet in CIDR notation (e.g., `192.168.1.0/24`).
  - **Returns:** List of discovered devices.

#### 7. Read All Device Properties
- **POST /bacnet/read_device_all**
  - **Description:** Read all standard properties from a BACnet device.
  - **Form Data:**
    - `device_address`, `device_object_identifier`
  - **Returns:** All properties as JSON.

#### 8. Who-Is
- **POST /bacnet/who_is**
  - **Description:** Send a Who-Is request to a BACnet address or range.
  - **Form Data:**
    - `device_instance_low`, `device_instance_high`, `dest`
  - **Returns:** List of devices found.

#### 9. Get Local IP
- **GET /get_local_ip**
  - **Description:** Returns the local IP address your machine would use to reach a given BACnet device or network.
  - **Query Parameter:**
    - `target_ip`: The IP address of the BACnet device or network you want to reach.
  - **Returns:** Local IP address

You can also use the interactive API documentation:
- Swagger UI: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- ReDoc: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)