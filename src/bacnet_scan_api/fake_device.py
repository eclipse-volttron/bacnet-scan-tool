"""Run a small fake BACnet device for scan-tool testing."""

import argparse
import asyncio
import random
from collections.abc import Iterable
from dataclasses import dataclass

import BAC0
from bacpypes3.basetypes import EngineeringUnits
from bacpypes3.object import (
    AnalogInputObject,
    AnalogOutputObject,
    AnalogValueObject,
    BinaryInputObject,
)
from bacpypes3.primitivedata import Real


@dataclass(frozen=True)
class FakeDeviceConfig:
    ip: str | None = None
    port: int | None = None
    update_interval: float = 10.0
    run_seconds: float | None = None
    no_ping: bool = False


def build_fake_objects() -> list:
    """Create a representative set of BACnet objects for scan testing."""
    return [
        AnalogInputObject(
            objectIdentifier=("analogInput", 1),
            objectName="Temperature_Sensor_1",
            presentValue=Real(22.5),
            units=EngineeringUnits("degreesCelsius"),
            description="Room Temperature Sensor",
        ),
        AnalogInputObject(
            objectIdentifier=("analogInput", 2),
            objectName="Temperature_Sensor_2",
            presentValue=Real(24.1),
            units=EngineeringUnits("degreesCelsius"),
            description="Outdoor Temperature Sensor",
        ),
        AnalogInputObject(
            objectIdentifier=("analogInput", 3),
            objectName="Humidity_Sensor_1",
            presentValue=Real(45.2),
            units=EngineeringUnits("percent"),
            description="Room Humidity Sensor",
        ),
        AnalogOutputObject(
            objectIdentifier=("analogOutput", 1),
            objectName="Damper_Position_1",
            presentValue=Real(75.0),
            units=EngineeringUnits("percent"),
            description="VAV Damper Position",
        ),
        BinaryInputObject(
            objectIdentifier=("binaryInput", 1),
            objectName="Door_Status_1",
            presentValue="inactive",
            description="Main Door Status",
        ),
        AnalogValueObject(
            objectIdentifier=("analogValue", 1),
            objectName="Temperature_Setpoint_1",
            presentValue=Real(21.0),
            units=EngineeringUnits("degreesCelsius"),
            description="Room Temperature Setpoint",
        ),
    ]


def add_objects(bp3_app, objects: Iterable) -> None:
    for obj in objects:
        bp3_app.add_object(obj)
        print(f"Added {obj.objectName} ({obj.objectIdentifier})")


def print_objects(bp3_app) -> None:
    print("\nCurrent BACnet objects:")
    for obj in bp3_app.iter_objects():
        object_name = getattr(obj, "objectName", "<unnamed>")
        print(f"  - {obj.objectIdentifier}: {object_name}")


def update_values(objects: list, cycle: int) -> None:
    temp_sensor_1, temp_sensor_2, humidity_sensor, damper_control, door_sensor, _ = objects

    temp_sensor_1.presentValue = Real(round(20 + random.uniform(-5, 5), 1))
    temp_sensor_2.presentValue = Real(round(22 + random.uniform(-3, 3), 1))
    humidity_sensor.presentValue = Real(round(45 + random.uniform(-10, 10), 1))
    damper_control.presentValue = Real(round(random.uniform(0, 100), 1))

    if random.random() < 0.1:
        door_sensor.presentValue = (
            "active" if door_sensor.presentValue == "inactive" else "inactive"
        )

    print(f"\nUpdated values (cycle {cycle}):")
    print(f"  Temp1: {temp_sensor_1.presentValue} C")
    print(f"  Temp2: {temp_sensor_2.presentValue} C")
    print(f"  Humidity: {humidity_sensor.presentValue}%")
    print(f"  Damper: {damper_control.presentValue}%")
    print(f"  Door: {door_sensor.presentValue}")


async def run_fake_device(config: FakeDeviceConfig) -> None:
    start_kwargs = {
        "ip": config.ip,
        "port": config.port,
        "ping": not config.no_ping,
    }
    start_kwargs = {key: value for key, value in start_kwargs.items() if value is not None}

    async with BAC0.start(**start_kwargs) as bacnet:
        print("BAC0 started successfully")
        print(f"Device ID: {bacnet.vendorId}, IP: {bacnet.localIPAddr}")

        bp3_app = bacnet.this_application.app
        objects = build_fake_objects()
        add_objects(bp3_app, objects)
        print_objects(bp3_app)

        print("\nFake BACnet device is running.")
        print("Scan it from the BACnet scan API to see the test objects.")

        cycle = 0
        loop = asyncio.get_running_loop()
        stop_at = loop.time() + config.run_seconds if config.run_seconds else None

        while True:
            if stop_at is not None and loop.time() >= stop_at:
                print("\nRun time reached; shutting down fake BACnet device.")
                return

            sleep_time = config.update_interval
            if stop_at is not None:
                sleep_time = min(sleep_time, max(stop_at - loop.time(), 0))
            await asyncio.sleep(sleep_time)

            if stop_at is not None and loop.time() >= stop_at:
                print("\nRun time reached; shutting down fake BACnet device.")
                return

            cycle += 1
            update_values(objects, cycle)


def parse_args() -> FakeDeviceConfig:
    parser = argparse.ArgumentParser(
        description="Run a fake BACnet device with sample points for testing scans."
    )
    parser.add_argument(
        "--ip",
        help="Local BACnet/IP address or interface override to pass to BAC0.",
    )
    parser.add_argument(
        "--port",
        type=int,
        help="Local BACnet/IP UDP port. Defaults to BAC0's default.",
    )
    parser.add_argument(
        "--update-interval",
        type=float,
        default=10.0,
        help="Seconds between simulated value updates.",
    )
    parser.add_argument(
        "--run-seconds",
        type=float,
        help="Stop automatically after this many seconds. Useful for smoke tests.",
    )
    parser.add_argument(
        "--no-ping",
        action="store_true",
        help="Disable BAC0 startup ping behavior.",
    )
    args = parser.parse_args()

    return FakeDeviceConfig(
        ip=args.ip,
        port=args.port,
        update_interval=args.update_interval,
        run_seconds=args.run_seconds,
        no_ping=args.no_ping,
    )


def main() -> None:
    try:
        asyncio.run(run_fake_device(parse_args()))
    except KeyboardInterrupt:
        print("\nShutting down fake BACnet device.")


if __name__ == "__main__":
    main()
