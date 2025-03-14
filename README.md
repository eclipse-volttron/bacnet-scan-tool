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

To activate the virtual environment created by Poetry, use:

```bash
source $(poetry env info --path)/bin/activate
```

## Run

The `bacnet-scan-tool` is a web-based interface tool built using FastAPI. To start the web server, use the following command:

```bash
uvicorn bacnet_scan_tool.main:app --reload
```

This will start the server on `http://127.0.0.1:8000`.

### API Documentation

FastAPI provides an interactive Swagger UI for API documentation. Once the server is running, you can access it at:

- Swagger UI: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- ReDoc: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

Use these endpoints to explore and test the API.

### Example Usage

1. Start the BACnet discovery process:
   ```bash
   curl -X GET "http://127.0.0.1:8000/bacnet/scan/start?ip_address=192.168.1.1"
   ```

2. Retrieve the list of discovered devices:
   ```bash
   curl -X GET "http://127.0.0.1:8000/devices"
   ```

3. Retrieve points for a specific device:
   ```bash
   curl -X GET "http://127.0.0.1:8000/devices/{device_id}/points"
   ```

4. Add a tag to a point:
   ```bash
   curl -X POST "http://127.0.0.1:8000/devices/{device_id}/points/{point_id}/tags" \
   -H "Content-Type: application/json" \
   -d '{"name": "example_tag"}'
   ```
