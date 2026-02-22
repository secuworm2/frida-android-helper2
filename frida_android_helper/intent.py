import os
import tempfile

from frida_android_helper.utils import *

try:
    from androguard.core.apk import APK
except ImportError:
    # Backward compatibility with older androguard layouts.
    from androguard.core.bytecodes.apk import APK

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


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


def list_activities(packagename=None):
    for device in get_adb_devices():
        eprint("Device: {} ({})".format(get_device_model(device), device.get_serial_no()))
        current_package = packagename or get_current_app_focus(device)
        if current_package is None:
            eprint("No app is open, specify package name.")
            continue

        eprint("Listing activities for {}...".format(current_package))
        apk_paths = _get_apk_paths(device, current_package)
        if not apk_paths:
            eprint("Failed to locate APK path for {}.".format(current_package))
            continue

        all_activities = []
        with tempfile.TemporaryDirectory(prefix="fah_manifest_") as temp_dir:
            for index, apk_path in enumerate(apk_paths):
                local_apk = os.path.join(temp_dir, "apk_{}.apk".format(index))
                try:
                    device.pull(apk_path, local_apk)
                except Exception as err:
                    eprint("Failed to pull APK {}: {}".format(apk_path, err))
                    continue

                activities = _extract_activities_from_manifest(local_apk, current_package)
                if activities is None:
                    continue
                all_activities.extend(activities)

        activities = list(dict.fromkeys(all_activities))
        if not activities:
            eprint("No activities found for {}.".format(current_package))
            continue

        for index, component in enumerate(activities, start=1):
            print("[{}] {}".format(index, component))
