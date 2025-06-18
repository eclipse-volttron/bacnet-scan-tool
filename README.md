# BACnet Scan Tool

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

## Run

The `bacnet-scan-tool` is a web-based interface tool built using FastAPI. To start the web server, use the following command:

```bash
poetry run uvicorn bacnet_scan_tool.main:app --reload
```

This will start the server on `http://127.0.0.1:8000`.

## Usage

### Start the FastAPI Web Server

Start the server with Poetry:

```bash
poetry run uvicorn bacnet_scan_tool.main:app --reload
```

The server will be available at [http://127.0.0.1:8000](http://127.0.0.1:8000).

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
  - **Returns:** Local IP address.

---

You can also use the interactive API documentation:
- Swagger UI: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- ReDoc: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
