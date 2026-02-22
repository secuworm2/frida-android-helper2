from datetime import datetime
import os
import re
import time

from frida_android_helper.utils import *


NETCAP_REMOTE_DIR = "/data/local/tmp"
NETCAP_PID_FILE = "{}/fah_netcap.pid".format(NETCAP_REMOTE_DIR)
NETCAP_PATH_FILE = "{}/fah_netcap.path".format(NETCAP_REMOTE_DIR)


def _is_root_available(device):
    result = perform_cmd(device, "su -c id")
    return "uid=0" in result


def _has_remote_file(device, path):
    result = perform_cmd(device, "su -c 'if [ -f {} ]; then echo 1; fi'".format(path))
    return result.strip() == "1"


def _read_remote_file(device, path):
    if not _has_remote_file(device, path):
        return ""
    return perform_cmd(device, "su -c 'cat {}'".format(path)).strip()


def _is_pid_running(device, pid):
    if not re.fullmatch(r"\d+", pid or ""):
        return False
    result = perform_cmd(device, "su -c 'kill -0 {} >/dev/null 2>&1; echo $?'".format(pid)).strip()
    return result == "0"


def _resolve_tcpdump_path(device):
    default_path = perform_cmd(device, "su -c 'command -v tcpdump'").strip()
    if default_path:
        return default_path

    fallback_paths = (
        "/data/local/tmp/tcpdump",
        "/system/bin/tcpdump",
        "/system/xbin/tcpdump",
    )
    for path in fallback_paths:
        result = perform_cmd(device, "su -c 'if [ -x {} ]; then echo {}; fi'".format(path, path)).strip()
        if result:
            return result
    return None


def _sanitize_filename(value):
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", value)
    return safe.strip("_") or "device"


def _cleanup_remote_netcap_state(device, remote_pcap=None):
    targets = [NETCAP_PID_FILE, NETCAP_PATH_FILE]
    if remote_pcap:
        targets.insert(0, remote_pcap)
    perform_cmd(device, "su -c 'rm -f {}'".format(" ".join(targets)))


def _supports_uid_filter(device, tcpdump_path):
    output = perform_cmd(
        device,
        "su -c '{} -ddd \"uid 0\" >/dev/null 2>&1; echo $?'".format(tcpdump_path),
    ).strip()
    code = output.splitlines()[-1].strip() if output else ""
    return code == "0"


def _get_package_uid(device, packagename):
    cmd_output = perform_cmd(
        device,
        "su -c 'cmd package list packages -U {}'".format(packagename),
    ).strip()
    for line in cmd_output.splitlines():
        match = re.search(r"uid:(\d+)", line)
        if match:
            return match.group(1)

    dumpsys_output = perform_cmd(device, "su -c 'dumpsys package {}'".format(packagename))
    match = re.search(r"\buserId=(\d+)", dumpsys_output or "")
    if match:
        return match.group(1)
    return None


def start_netcap(packagename=None):
    eprint("Starting network capture...")
    for device in get_adb_devices():
        serial = device.get_serial_no()
        eprint("Device: {} ({})".format(get_device_model(device), serial))

        if not _is_root_available(device):
            eprint("Root is required for tcpdump capture.")
            continue

        tcpdump_path = _resolve_tcpdump_path(device)
        if not tcpdump_path:
            eprint("tcpdump not found on device.")
            eprint("Put a compatible tcpdump binary at /data/local/tmp/tcpdump and chmod 755 it.")
            continue

        current_pid = _read_remote_file(device, NETCAP_PID_FILE)
        if _is_pid_running(device, current_pid):
            eprint("Capture is already running (pid {}). Run 'fah netcap stop' first.".format(current_pid))
            continue

        bpf_filter = ""
        if packagename:
            uid = _get_package_uid(device, packagename)
            if not uid:
                eprint("Package '{}' not found or UID lookup failed.".format(packagename))
                continue
            if not _supports_uid_filter(device, tcpdump_path):
                eprint("This tcpdump build does not support 'uid' capture filters.")
                eprint("Use 'fah netcap start' without package filter on this device.")
                continue
            bpf_filter = "\"uid {}\"".format(uid)
            eprint("Applying package filter: {} (uid={})".format(packagename, uid))

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        remote_pcap = "{}/fah_netcap_{}_{}.pcap".format(
            NETCAP_REMOTE_DIR,
            _sanitize_filename(serial),
            timestamp,
        )
        cmd = (
            "su -c '"
            "rm -f {pid_file}; "
            "echo {pcap} > {path_file}; "
            "{tcpdump} -i any -s 0 -U -w {pcap} {bpf_filter} >/dev/null 2>&1 & "
            "echo $! > {pid_file}; "
            "cat {pid_file}"
            "'"
        ).format(
            pid_file=NETCAP_PID_FILE,
            path_file=NETCAP_PATH_FILE,
            tcpdump=tcpdump_path,
            pcap=remote_pcap,
            bpf_filter=bpf_filter,
        )
        pid_output = perform_cmd(device, cmd).strip()
        pid = pid_output.splitlines()[-1].strip() if pid_output else ""

        if not re.fullmatch(r"\d+", pid):
            eprint("Failed to start capture. Output: {}".format(pid_output or "<empty>"))
            continue

        print("Capture started: pid={} file={}".format(pid, remote_pcap))


def stop_netcap():
    eprint("Stopping network capture...")
    for device in get_adb_devices():
        serial = device.get_serial_no()
        eprint("Device: {} ({})".format(get_device_model(device), serial))

        if not _is_root_available(device):
            eprint("Root is required to stop capture.")
            continue

        pid = _read_remote_file(device, NETCAP_PID_FILE)
        remote_pcap = _read_remote_file(device, NETCAP_PATH_FILE)

        if not pid and not remote_pcap:
            eprint("No active netcap state found.")
            continue

        if _is_pid_running(device, pid):
            perform_cmd(device, "su -c 'kill -2 {}'".format(pid))
            time.sleep(1)

        if not remote_pcap:
            eprint("Capture path not found. Only clearing state files.")
            _cleanup_remote_netcap_state(device)
            continue

        if not _has_remote_file(device, remote_pcap):
            eprint("Capture file not found on device: {}".format(remote_pcap))
            _cleanup_remote_netcap_state(device)
            continue

        local_name = os.path.basename(remote_pcap)
        if os.path.exists(local_name):
            base, ext = os.path.splitext(local_name)
            local_name = "{}_{}{}".format(base, datetime.now().strftime("%Y%m%d_%H%M%S"), ext or ".pcap")

        try:
            device.pull(remote_pcap, local_name)
            print("Capture saved: {}".format(local_name))
        except Exception as err:
            eprint("Failed to pull capture file: {}".format(err))
            eprint("Pull failed, but remote capture file will still be removed.")
        finally:
            _cleanup_remote_netcap_state(device, remote_pcap)
