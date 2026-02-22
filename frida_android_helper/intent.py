import re

from frida_android_helper.utils import *

_COMPONENT_PATTERN = re.compile(r"([A-Za-z0-9_.$]+/[A-Za-z0-9_.$]+)")
_ACTIVITY_OBJECT_PATTERN = re.compile(r"(?:Activity|ActivityAlias)\{[^}]*\s([A-Za-z0-9_.$]+/[A-Za-z0-9_.$]+)\}")
_CLASS_HEADER_PATTERN = re.compile(r"^([A-Za-z0-9_.$]+):$")
_CLASS_ASSIGNMENT_PATTERN = re.compile(r"(?:Class=|name=)([A-Za-z0-9_.$]+)")
_SECTION_HEADER_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9 ]+:$")


def _normalize_component(packagename, component):
    if "/" in component:
        component_pkg, component_name = component.split("/", 1)
        if component_pkg != packagename:
            return None
        if component_name.startswith("."):
            component_name = "{}{}".format(packagename, component_name)
        return "{}/{}".format(packagename, component_name)

    if component.startswith("."):
        component = "{}{}".format(packagename, component)
    if not component.startswith("{}.".format(packagename)):
        return None
    return "{}/{}".format(packagename, component)


def _extract_activity_components(packagename, package_dump):
    components = []
    in_activity_resolver = False
    in_activities = False
    activities_indent = None
    activity_resolver_indent = None

    for raw_line in package_dump.splitlines():
        indent = len(raw_line) - len(raw_line.lstrip())
        line = raw_line.strip()

        if line.lower() == "activities:":
            in_activities = True
            activities_indent = indent
            in_activity_resolver = False
            activity_resolver_indent = None
            continue

        if in_activities and _SECTION_HEADER_PATTERN.match(line) and indent <= activities_indent:
            if line.lower() != "activities:":
                in_activities = False
                activities_indent = None
                in_activity_resolver = False
                activity_resolver_indent = None

        if in_activities and line == "Activity Resolver Table:":
            in_activity_resolver = True
            activity_resolver_indent = indent
            continue

        if in_activity_resolver and line.endswith("Resolver Table:") and line != "Activity Resolver Table:":
            if activity_resolver_indent is None or indent <= activity_resolver_indent:
                in_activity_resolver = False
                activity_resolver_indent = None

        if in_activity_resolver:
            for component in _COMPONENT_PATTERN.findall(line):
                normalized = _normalize_component(packagename, component)
                if normalized:
                    components.append(normalized)

        if in_activities:
            for component in _COMPONENT_PATTERN.findall(line):
                normalized = _normalize_component(packagename, component)
                if normalized:
                    components.append(normalized)

            class_header_match = _CLASS_HEADER_PATTERN.match(line)
            if class_header_match:
                normalized = _normalize_component(packagename, class_header_match.group(1))
                if normalized:
                    components.append(normalized)

            for class_name in _CLASS_ASSIGNMENT_PATTERN.findall(line):
                normalized = _normalize_component(packagename, class_name)
                if normalized:
                    components.append(normalized)

    # Package dump commonly contains full activity declarations as Activity{... pkg/.Class}.
    # Parse these globally so we do not miss non-exported activities.
    for component in _ACTIVITY_OBJECT_PATTERN.findall(package_dump):
        normalized = _normalize_component(packagename, component)
        if normalized:
            components.append(normalized)

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
