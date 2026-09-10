import os
from frida_android_helper.utils import *
from ppadb.device import Device as AdbDevice

NATIVE_STAGING_DIR = "/data/local/tmp/"


def _resolve_target_package(device: AdbDevice, packagename):
    if packagename:
        return packagename
    return get_current_app_focus(device)


def _get_target_pid(device: AdbDevice, packagename: str):
    pid = perform_cmd(device, "pidof {}".format(packagename), root=True).strip()
    if not pid:
        eprint("ERROR: {} does not appear to be running.".format(packagename))
        return None
    return pid.split()[0]


def _get_loaded_native_libs(device: AdbDevice, packagename: str):
    pid = _get_target_pid(device, packagename)
    if pid is None:
        return None, None

    maps_output = perform_cmd(device, "cat /proc/{}/maps".format(pid), root=True)
    if not maps_output:
        eprint("ERROR: Failed to read /proc/{}/maps for {}.".format(pid, packagename))
        return pid, None

    libs = {}
    for line in maps_output.splitlines():
        parts = line.strip().split(None, 5)
        if len(parts) < 6:
            continue

        addr_range = parts[0]
        path = parts[5].strip()

        deleted = path.endswith(" (deleted)")
        if deleted:
            path = path[: -len(" (deleted)")]

        if not path.endswith(".so"):
            continue

        name = os.path.basename(path)
        if name not in libs:
            libs[name] = {"path": path, "deleted": deleted, "addr_range": addr_range}

    return pid, libs


def _is_app_path(path: str):
    return path.startswith("/data/app/") or path.startswith("/data/data/") or path.startswith("/data/user/")


def list_native_libs(packagename=None):
    for device in get_adb_devices():
        eprint("Device: {} ({})".format(get_device_model(device), device.get_serial_no()))
        target = _resolve_target_package(device, packagename)
        if not target:
            eprint("No app is open, specify package name.")
            continue

        pid, libs = _get_loaded_native_libs(device, target)
        if not libs:
            if pid:
                eprint("No native libraries found for {} (pid {}).".format(target, pid))
            continue

        eprint("{} (pid {}) — {} native librar{}:".format(target, pid, len(libs), "y" if len(libs) == 1 else "ies"))

        app_libs = []
        system_libs = []
        for name, info in sorted(libs.items()):
            (app_libs if _is_app_path(info["path"]) else system_libs).append((name, info))

        if app_libs:
            print("-- App-provided --")
            for name, info in app_libs:
                tag = "  [DELETED after load — self-erasing, likely packed/protected]" if info["deleted"] else ""
                print("  {}  ({}){}".format(name, info["path"], tag))
        if system_libs:
            print("-- System / framework --")
            for name, info in system_libs:
                tag = "  [DELETED after load]" if info["deleted"] else ""
                print("  {}  ({}){}".format(name, info["path"], tag))


def download_native_lib(packagename, filename):
    for device in get_adb_devices():
        eprint("Device: {} ({})".format(get_device_model(device), device.get_serial_no()))
        target = _resolve_target_package(device, packagename)
        if not target:
            eprint("No app is open, specify package name.")
            continue

        pid, libs = _get_loaded_native_libs(device, target)
        if not libs:
            continue

        info = libs.get(filename)
        if info is None:
            eprint("ERROR: '{}' is not among the libraries currently loaded by {}.".format(filename, target))
            eprint("Available: {}".format(", ".join(sorted(libs.keys()))))
            continue

        staged_path = "{}{}".format(NATIVE_STAGING_DIR, filename)

        if info["deleted"]:
            eprint("{} was unlinked from disk after loading (self-erasing) — recovering from process memory...".format(filename))
            remote_source = "/proc/{}/map_files/{}".format(pid, info["addr_range"])
        else:
            remote_source = info["path"]

        result = perform_cmd(device, "cp '{}' '{}' && echo OK".format(remote_source, staged_path), root=True).strip()
        if not result.endswith("OK"):
            eprint("ERROR: Failed to copy {} on device: {}".format(remote_source, result))
            continue
        perform_cmd(device, "chmod 644 '{}'".format(staged_path), root=True)

        eprint("Pulling {} ...".format(remote_source))
        try:
            device.pull(staged_path, filename)
        except Exception as err:
            eprint("ERROR: {}".format(err))
            continue
        perform_cmd(device, "rm -f '{}'".format(staged_path), root=True)

        if os.path.isfile(filename) and os.path.getsize(filename) > 0:
            eprint("Saved to ./{} ({} bytes).".format(filename, os.path.getsize(filename)))
        else:
            eprint("ERROR: Pull appears to have failed — {} is missing or empty locally.".format(filename))
