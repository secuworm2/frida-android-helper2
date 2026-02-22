from datetime import datetime
import os

from frida_android_helper.utils import *
import frida


def _resolve_target_package(device, packagename):
    if packagename:
        return packagename

    focused = get_current_app_focus(device)
    if focused:
        return focused
    return None


def _resolve_launcher_component(device, packagename):
    output = perform_cmd(device, "cmd package resolve-activity --brief {}".format(packagename))
    for line in reversed(output.splitlines()):
        candidate = line.strip()
        if "/" not in candidate:
            continue
        if candidate.startswith(packagename):
            return candidate
    return None


def download_app(packagename=None):
    eprint("Downloading app...")
    for device in get_adb_devices():
        eprint("Device: {} ({})".format(get_device_model(device), device.get_serial_no()))
        if packagename is None:
            packagename = get_current_app_focus(device)
            if packagename is None:
                eprint("No app is open, specify package name.")
                continue
            packagenames = [packagename]
        else:
            packagenames = list_apps_for_device(device, packagename)

        if not packagenames:
            eprint("No package with filter '{}' was found".format(packagename))

        for target in packagenames:
            eprint("Querying path info for {}...".format(target))
            path = perform_cmd(device, "pm path {}".format(target))
            packages = [p.replace("package:", "") for p in path.splitlines()]

            if not packages:
                eprint("{} package does not exist.".format(target))
                continue

            folder = "{}_{}".format(target, datetime.now().strftime("%Y.%m.%d_%H.%M.%S"))
            eprint("Creating directory {}...".format(folder))
            os.mkdir(folder)

            for package_path in packages:
                save_package = "{}/{}".format(folder, os.path.basename(package_path))
                eprint("Downloading from {} to {}...".format(package_path, save_package))
                device.pull(package_path, save_package)


def list_apps(filter=None):
    if filter is None:
        filter = ""
        eprint("Listing apps...")
    else:
        eprint("Listing apps using filter '{}'...".format(filter))

    for device in get_adb_devices():
        eprint("Device: {} ({})".format(get_device_model(device), device.get_serial_no()))
        frida_device = frida.get_device(device.get_serial_no())
        for app in frida_device.enumerate_applications():
            if filter.lower() in app.identifier.lower() or filter.lower() in app.name.lower():
                print("- {} ({}) [{}]".format(app.name, app.identifier, app.pid))


def list_apps_for_device(device, filter=None):
    return [package for package in device.list_packages() if filter in package]


def start_app(packagename=None):
    eprint("Starting app...")
    for device in get_adb_devices():
        eprint("Device: {} ({})".format(get_device_model(device), device.get_serial_no()))
        target = _resolve_target_package(device, packagename)
        if target is None:
            eprint("No app is open, specify package name.")
            continue

        component = _resolve_launcher_component(device, target)
        if component:
            result = perform_cmd(device, "am start -n {}".format(component))
        else:
            # Fallback when launcher component cannot be resolved.
            result = perform_cmd(device, "monkey -p {} -c android.intent.category.LAUNCHER 1".format(target))

        if result:
            print(result.strip())


def stop_app(packagename=None):
    eprint("Stopping app...")
    for device in get_adb_devices():
        eprint("Device: {} ({})".format(get_device_model(device), device.get_serial_no()))
        target = _resolve_target_package(device, packagename)
        if target is None:
            eprint("No app is open, specify package name.")
            continue

        result = perform_cmd(device, "am force-stop {}".format(target))
        if result:
            print(result.strip())


def clear_app(packagename=None):
    eprint("Clearing app data...")
    for device in get_adb_devices():
        eprint("Device: {} ({})".format(get_device_model(device), device.get_serial_no()))
        target = _resolve_target_package(device, packagename)
        if target is None:
            eprint("No app is open, specify package name.")
            continue

        result = perform_cmd(device, "pm clear {}".format(target))
        if result:
            print(result.strip())
