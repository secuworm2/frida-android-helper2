import os
import re
from frida_android_helper.utils import *
from ppadb.device import Device as AdbDevice

NATIVE_STAGING_DIR = "/data/local/tmp/"

_ABI_BITNESS = {
    "arm64-v8a": 64, "x86_64": 64, "riscv64": 64, "mips64": 64,
    "armeabi-v7a": 32, "armeabi": 32, "x86": 32, "mips": 32,
}


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


def _is_app_path(path: str):
    return path.startswith("/data/app/") or path.startswith("/data/data/") or path.startswith("/data/user/")


def _is_app_dynamic(path: str):
    # App-writable locations where dynamically loaded code (dex/jar/apk) is dropped at runtime.
    return (path.startswith("/data/data/") or path.startswith("/data/user/")
            or path.startswith("/data/user_de/") or path.startswith("/data/local/"))


def _classify(path: str, perms: str):
    # Classify a file-backed (or named-anonymous) mapping into a loadable module kind.
    #   so     - native shared library
    #   apkso  - APK with executable code mapped in (extractNativeLibs=false); inner .so resolved
    #   dex    - dex / vdex / dynamically loaded jar|apk (dex container)
    #   dexmem - dex loaded in memory (InMemoryDexClassLoader), named [anon:dalvik-...classes.dex...]
    #   code   - other executable module: the main executable, the linker, .oat/.odex, ...
    if path.endswith(".so"):
        return "so"
    if path.endswith(".apk") and "x" in perms and _is_app_path(path):
        return "apkso"
    if path.endswith((".dex", ".cdex", ".vdex")):
        return "dex"
    if path.endswith((".jar", ".apk")) and _is_app_dynamic(path):
        return "dex"
    if path.startswith("[anon:") and ".dex" in path:
        return "dexmem"
    if "x" in perms and path.startswith("/") and not path.startswith(("/dev/", "/memfd:")):
        return "code"
    return None


def _module_name(path: str, kind: str):
    if kind == "dexmem":
        inner = path[len("[anon:"):].rstrip("]")
        if inner.startswith("dalvik-"):
            inner = inner[len("dalvik-"):]
        return os.path.basename(inner) if "/" in inner else inner
    return os.path.basename(path)


def _get_device_abis(device: AdbDevice):
    raw = perform_cmd(device, "getprop ro.product.cpu.abilist") or ""
    abis = [a.strip() for a in raw.strip().split(",") if a.strip()]
    if not abis:
        primary = (perform_cmd(device, "getprop ro.product.cpu.abi") or "").strip()
        if primary:
            abis = [primary]
    return abis


def _list_apk_native_libs(device: AdbDevice, apk_path: str, abis):
    # Modern apps ship with extractNativeLibs=false, so their .so files are
    # mapped straight out of the APK and /proc/<pid>/maps shows the backing
    # .apk path, not the .so. Enumerate the libraries inside the APK so they
    # are visible. Returns {soname: zip_entry_path}.
    out = perform_cmd(device, "unzip -l '{}'".format(apk_path), root=True) or ""
    found = {}
    for line in out.splitlines():
        token = line.strip().split()
        if not token:
            continue
        entry = token[-1]
        if not entry.endswith(".so"):
            continue
        parts = entry.split("/")
        if len(parts) < 3 or parts[0] != "lib":
            continue
        if abis and parts[1] not in abis:
            continue
        found.setdefault(parts[-1], entry)
    return found


def _get_loaded_native_libs(device: AdbDevice, packagename: str):
    pid = _get_target_pid(device, packagename)
    if pid is None:
        return None, None

    maps_output = perform_cmd(device, "cat /proc/{}/maps".format(pid), root=True)
    if not maps_output:
        eprint("ERROR: Failed to read /proc/{}/maps for {}.".format(pid, packagename))
        return pid, None

    libs = {}
    exec_apks = {}  # apk_path -> addr_range of an executable mapping (for reference)
    is_64bit = False
    for line in maps_output.splitlines():
        parts = line.strip().split(None, 5)
        if len(parts) < 6:
            continue

        addr_range = parts[0]
        perms = parts[1]
        path = parts[5].strip()

        if "lib64" in path or "/arm64" in path or "/x86_64" in path:
            is_64bit = True

        deleted = path.endswith(" (deleted)")
        if deleted:
            path = path[: -len(" (deleted)")]

        kind = _classify(path, perms)
        if kind is None:
            continue
        if kind == "apkso":
            # Executable code mapped directly from an APK (extractNativeLibs=false).
            exec_apks.setdefault(path, addr_range)
            continue

        name = _module_name(path, kind)
        if name and path not in libs:
            libs[path] = {"name": name, "path": path, "deleted": deleted, "addr_range": addr_range,
                          "source": "memory" if kind == "dexmem" else "fs", "kind": kind}

    if exec_apks:
        abis = _get_device_abis(device)
        if abis:
            abis = [a for a in abis if _ABI_BITNESS.get(a) == (64 if is_64bit else 32)] or abis
        for apk_path in exec_apks:
            for name, entry in _list_apk_native_libs(device, apk_path, abis).items():
                synthetic = "{}!/{}".format(apk_path, entry)
                if synthetic not in libs:
                    libs[synthetic] = {"name": name, "path": synthetic, "deleted": False,
                                       "addr_range": exec_apks[apk_path], "source": "apk",
                                       "apk": apk_path, "entry": entry, "kind": "so"}

    return pid, libs


def _container(info):
    # (sort_key, display, note) describing where a module lives, shown once per group.
    if info.get("source") == "apk":
        return info["apk"], info["apk"], "mapped from APK, extractNativeLibs=false"
    if info.get("source") == "memory":
        return "￿-memory", "[in-memory]", "dynamically loaded dex (no backing file)"
    directory = os.path.dirname(info["path"])
    return directory, directory, ""


def _lib_flag(info):
    if info["deleted"]:
        return "  [!] self-erased (unlinked after load)"
    return ""


def _print_group(libs):
    groups = {}
    for name, info in libs:
        key, display, note = _container(info)
        groups.setdefault(key, (display, note, []))[2].append((name, info))
    for key in sorted(groups):
        display, note, members = groups[key]
        print("  {}{}".format(display, "  - " + note if note else ""))
        for name, info in sorted(members):
            print("    {}{}".format(name, _lib_flag(info)))


def list_native_libs(packagename=None, show_all=False):
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

        app_libs = []
        system_libs = []
        for info in sorted(libs.values(), key=lambda i: i["name"]):
            (app_libs if target in info["path"] else system_libs).append((info["name"], info))

        shown = len(app_libs) + (len(system_libs) if show_all else 0)
        eprint("{} (pid {}) — {} loaded module{}{}".format(
            target, pid, shown, "" if shown == 1 else "s",
            "" if show_all else " (app-provided; use --all for system/framework)"))

        if app_libs:
            print("\n[ App-provided ]  ({})".format(len(app_libs)))
            _print_group(app_libs)
        if show_all and system_libs:
            print("\n[ System / framework ]  ({})".format(len(system_libs)))
            _print_group(system_libs)


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

        matches = [i for i in libs.values() if i["name"] == filename]
        if not matches:
            eprint("ERROR: '{}' is not among the modules currently loaded by {}.".format(filename, target))
            eprint("Available: {}".format(", ".join(sorted(set(i["name"] for i in libs.values())))))
            continue
        if len(matches) > 1:
            app_matches = [i for i in matches if target in i["path"]]
            if len(app_matches) == 1:
                matches = app_matches
            else:
                eprint("ERROR: '{}' is ambiguous — {} modules share that name:".format(filename, len(matches)))
                for i in matches:
                    eprint("  {}".format(i["path"]))
                continue
        info = matches[0]

        staged_path = "{}{}".format(NATIVE_STAGING_DIR, filename)

        if info.get("source") == "apk":
            eprint("{} is mapped from {} (extractNativeLibs=false) — extracting from the APK...".format(
                filename, os.path.basename(info["apk"])))
            extract_cmd = "unzip -p '{}' '{}' > '{}'".format(info["apk"], info["entry"], staged_path)
        elif info.get("source") == "memory" or info["deleted"]:
            reason = "loaded in memory (no backing file)" if info.get("source") == "memory" \
                else "unlinked from disk after loading (self-erasing)"
            eprint("{} is {} — recovering from process memory...".format(filename, reason))
            extract_cmd = "cp '/proc/{}/map_files/{}' '{}'".format(pid, info["addr_range"], staged_path)
        else:
            extract_cmd = "cp '{}' '{}'".format(info["path"], staged_path)

        perform_cmd(device, extract_cmd, root=True)
        size = (perform_cmd(device, "wc -c < '{}'".format(staged_path), root=True) or "0").strip()
        if not size.isdigit() or int(size) == 0:
            eprint("ERROR: Failed to stage {} on device (got {} bytes).".format(filename, size or "0"))
            perform_cmd(device, "rm -f '{}'".format(staged_path), root=True)
            continue
        perform_cmd(device, "chmod 644 '{}'".format(staged_path), root=True)

        eprint("Pulling {} ...".format(filename))
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
