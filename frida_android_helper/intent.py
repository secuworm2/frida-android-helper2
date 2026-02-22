import re

from frida_android_helper.utils import *

_COMPONENT_PATTERN = re.compile(r"([A-Za-z0-9_.$]+/[A-Za-z0-9_.$]+)")
_SECTION_END_PATTERN = re.compile(r"^[A-Z][A-Za-z0-9 ]+:$")


def _extract_activity_components(packagename, package_dump):
    components = []
    in_activity_resolver = False
    in_activities = False

    for raw_line in package_dump.splitlines():
        line = raw_line.strip()

        if line == "Activity Resolver Table:":
            in_activity_resolver = True
            continue
        if line == "Activities:":
            in_activities = True
            continue

        if in_activity_resolver and line.endswith("Resolver Table:") and line != "Activity Resolver Table:":
            in_activity_resolver = False
            continue

        if in_activities and _SECTION_END_PATTERN.match(line) and line != "Activities:":
            in_activities = False
            continue

        if in_activity_resolver or in_activities:
            for component in _COMPONENT_PATTERN.findall(line):
                if component.startswith("{}/".format(packagename)):
                    components.append(component)

    if not components:
        for component in _COMPONENT_PATTERN.findall(package_dump):
            if component.startswith("{}/".format(packagename)):
                components.append(component)

    # Preserve order while removing duplicates.
    return list(dict.fromkeys(components))


def list_activities(packagename=None):
    for device in get_adb_devices():
        eprint("Device: {} ({})".format(get_device_model(device), device.get_serial_no()))
        current_package = packagename or get_current_app_focus(device)
        if current_package is None:
            eprint("No app is open, specify package name.")
            continue

        eprint("Listing activities for {}...".format(current_package))
        package_dump = perform_cmd(device, "dumpsys package {}".format(current_package))
        if not package_dump:
            eprint("Failed to query package dump for {}.".format(current_package))
            continue

        activities = _extract_activity_components(current_package, package_dump)
        if not activities:
            eprint("No activities found for {}.".format(current_package))
            continue

        for index, component in enumerate(activities, start=1):
            print("[{}] {}".format(index, component))
