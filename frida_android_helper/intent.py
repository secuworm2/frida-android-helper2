import os
import tempfile
import logging

from frida_android_helper.utils import *

try:
    from androguard.core.apk import APK
except ImportError:
    # Backward compatibility with older androguard layouts.
    from androguard.core.bytecodes.apk import APK

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def _silence_androguard_logs():
    logging.getLogger("androguard").setLevel(logging.WARNING)
    try:
        from loguru import logger
        logger.disable("androguard")
    except Exception:
        pass


_silence_androguard_logs()


def _normalize_activity_name(packagename, activity_name):
    if activity_name.startswith("."):
        fqcn = "{}{}".format(packagename, activity_name)
    elif "." in activity_name:
        fqcn = activity_name
    else:
        fqcn = "{}.{}".format(packagename, activity_name)
    return "{}/{}".format(packagename, fqcn)


def _get_apk_paths(device, packagename):
    result = perform_cmd(device, "pm path {}".format(packagename))
    paths = []
    for line in result.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            paths.append(line[len("package:"):])
    return paths


def _extract_activities_from_manifest(apk_path, fallback_packagename):
    try:
        apk = APK(apk_path)
    except Exception as err:
        eprint("Failed to parse APK manifest {}: {}".format(apk_path, err))
        return None

    try:
        manifest = apk.get_android_manifest_xml()
    except Exception as err:
        eprint("Failed to read AndroidManifest.xml from {}: {}".format(apk_path, err))
        return None

    if manifest is None:
        eprint("AndroidManifest.xml not found in {}.".format(apk_path))
        return None

    package_name = apk.get_package() or fallback_packagename
    activities = []
    for node in manifest.iter():
        tag = node.tag
        if not isinstance(tag, str):
            continue

        if "}" in tag:
            tag = tag.split("}", 1)[1]
        if tag not in ("activity", "activity-alias"):
            continue

        activity_name = node.get("{}name".format(ANDROID_NS)) or node.get("name")
        if not activity_name:
            continue

        activities.append(_normalize_activity_name(package_name, activity_name))

    return list(dict.fromkeys(activities))


def _collect_activities_for_device(device, packagename):
    apk_paths = _get_apk_paths(device, packagename)
    if not apk_paths:
        eprint("Failed to locate APK path for {}.".format(packagename))
        return []

    all_activities = []
    with tempfile.TemporaryDirectory(prefix="fah_manifest_") as temp_dir:
        for index, apk_path in enumerate(apk_paths):
            local_apk = os.path.join(temp_dir, "apk_{}.apk".format(index))
            try:
                device.pull(apk_path, local_apk)
            except Exception as err:
                eprint("Failed to pull APK {}: {}".format(apk_path, err))
                continue

            activities = _extract_activities_from_manifest(local_apk, packagename)
            if activities is None:
                continue
            all_activities.extend(activities)

    return list(dict.fromkeys(all_activities))


def _resolve_target_component(packagename, activities, target):
    if target is None:
        return None

    if target.isdigit():
        index = int(target)
        if index < 1 or index > len(activities):
            eprint("Invalid activity index: {} (valid range: 1-{})".format(index, len(activities)))
            return None
        return activities[index - 1]

    if "/" in target:
        if target.startswith("{}/".format(packagename)):
            return target
        eprint("Target component must start with '{}/'.".format(packagename))
        return None

    return _normalize_activity_name(packagename, target)


def _start_activity(device, component):
    eprint("Starting activity {}...".format(component))
    output = perform_cmd(device, "am start -n {}".format(component))
    denied_markers = (
        "Permission Denial",
        "not exported",
        "java.lang.SecurityException",
    )
    if any(marker in output for marker in denied_markers):
        eprint("Permission denied, retrying with root...")
        output = perform_cmd(device, "am start -n {}".format(component), root=True)
    if output:
        print(output.strip())


def list_activities(packagename=None, target=None):
    for device in get_adb_devices():
        eprint("Device: {} ({})".format(get_device_model(device), device.get_serial_no()))
        current_package = packagename or get_current_app_focus(device)
        if current_package is None:
            eprint("No app is open, specify package name.")
            continue

        eprint("Listing activities for {}...".format(current_package))
        activities = _collect_activities_for_device(device, current_package)
        if not activities:
            eprint("No activities found for {}.".format(current_package))
            continue

        if target is None:
            for index, component in enumerate(activities, start=1):
                print("[{}] {}".format(index, component))
            continue

        component = _resolve_target_component(current_package, activities, target)
        if component is None:
            continue
        _start_activity(device, component)
