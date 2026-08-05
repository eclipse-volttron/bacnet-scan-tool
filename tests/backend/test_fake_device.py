from bacnet_scan_api.fake_device import build_fake_objects, update_values


def test_build_fake_objects():
    objects = build_fake_objects()

    assert len(objects) == 6
    assert [obj.objectName for obj in objects] == [
        "Temperature_Sensor_1",
        "Temperature_Sensor_2",
        "Humidity_Sensor_1",
        "Damper_Position_1",
        "Door_Status_1",
        "Temperature_Setpoint_1",
    ]
    assert [str(obj.objectIdentifier) for obj in objects] == [
        "analog-input,1",
        "analog-input,2",
        "analog-input,3",
        "analog-output,1",
        "binary-input,1",
        "analog-value,1",
    ]


def test_update_values_keeps_expected_ranges():
    objects = build_fake_objects()

    update_values(objects, cycle=1)

    assert 15 <= float(objects[0].presentValue) <= 25
    assert 19 <= float(objects[1].presentValue) <= 25
    assert 35 <= float(objects[2].presentValue) <= 55
    assert 0 <= float(objects[3].presentValue) <= 100
    assert str(objects[4].presentValue) in {"active", "inactive"}
