import os
import re
import shutil
import subprocess
import tempfile

from frida_android_helper.utils import *

_MANIFEST_NAME_PATTERN = re.compile(r'A: android:name(?:\([^)]*\))?="([^"]+)"')


def _normalize_activity_name(packagename, activity_name):
    if activity_name.startswith("."):
        fqcn = "{}{}".format(packagename, activity_name)
    elif "." in activity_name:
        fqcn = activity_name
    else:
        fqcn = "{}.{}".format(packagename, activity_name)
    return "{}/{}".format(packagename, fqcn)


def _get_base_apk_path(device, packagename):
    result = perform_cmd(device, "pm path {}".format(packagename))
    paths = []
    for line in result.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            paths.append(line[len("package:"):])

    if not paths:
        return None

    for path in paths:
        if path.endswith("/base.apk"):
            return path
    return paths[0]


def _extract_activities_from_manifest(apk_path, packagename):
    aapt_path = shutil.which("aapt")
    if not aapt_path:
        eprint("aapt not found in PATH. Install Android build-tools or add aapt to PATH.")
        return None

    try:
        output = subprocess.run(
            [aapt_path, "dump", "xmltree", apk_path, "AndroidManifest.xml"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            check=False,
        )
    except Exception as err:
        eprint("Failed to run aapt: {}".format(err))
        return None

    if output.returncode != 0:
        eprint("aapt failed: {}".format(output.stderr.strip()))
        return None

    activities = []
    in_activity = False
    activity_indent = 0

    for raw_line in output.stdout.splitlines():
        indent = len(raw_line) - len(raw_line.lstrip())
        line = raw_line.strip()

        if line.startswith("E: activity ") or line.startswith("E: activity-alias "):
            in_activity = True
            activity_indent = indent
            continue

        if in_activity and line.startswith("E: ") and indent <= activity_indent:
            in_activity = False

        if not in_activity:
            continue

        match = _MANIFEST_NAME_PATTERN.search(line)
        if match:
            activities.append(_normalize_activity_name(packagename, match.group(1)))

    return list(dict.fromkeys(activities))


def list_activities(packagename=None):
    for device in get_adb_devices():
        eprint("Device: {} ({})".format(get_device_model(device), device.get_serial_no()))
        current_package = packagename or get_current_app_focus(device)
        if current_package is None:
            eprint("No app is open, specify package name.")
            continue

        eprint("Listing activities for {}...".format(current_package))
        apk_path = _get_base_apk_path(device, current_package)
        if apk_path is None:
            eprint("Failed to locate APK path for {}.".format(current_package))
            continue

        with tempfile.TemporaryDirectory(prefix="fah_manifest_") as temp_dir:
            local_apk = os.path.join(temp_dir, "base.apk")
            try:
                device.pull(apk_path, local_apk)
            except Exception as err:
                eprint("Failed to pull APK {}: {}".format(apk_path, err))
                continue

            activities = _extract_activities_from_manifest(local_apk, current_package)

        if activities is None:
            continue
        if not activities:
            eprint("No activities found for {}.".format(current_package))
            continue

        for index, component in enumerate(activities, start=1):
            print("[{}] {}".format(index, component))
