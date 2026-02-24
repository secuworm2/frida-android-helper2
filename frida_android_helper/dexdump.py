from datetime import datetime
from importlib import resources
import os
import subprocess
import time

import frida

from frida_android_helper.utils import *


def _message_callback(message, data):
    msg_type = message.get("type")
    if msg_type == "send":
        print(message.get("payload", ""))
    elif msg_type == "error":
        eprint("Frida error: {}".format(message.get("stack", message)))
    else:
        eprint("Frida message: {}".format(message))


def _resolve_target_package(device, packagename):
    if packagename:
        return packagename

    focused = get_current_app_focus(device)
    if focused:
        return focused
    return None


def _sanitize(value):
    return "".join([ch if ch.isalnum() or ch in "._-" else "_" for ch in value])


def _pull_with_adb(serial, remote_path, local_path):
    cmd = ["adb", "-s", serial, "pull", remote_path, local_path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout.strip())
    if result.returncode != 0 and result.stderr:
        eprint(result.stderr.strip())
    return result.returncode == 0


def _exists_dir(device, path, root=False):
    out = perform_cmd(device, "[ -d {} ] && echo 1 || echo 0".format(path), root=root)
    return out.strip() == "1"


def _load_dexdump_hook_script():
    return resources.files("frida_android_helper").joinpath("frida_hooks", "dump_dex.js").read_text(encoding="utf-8")


def run_dexdump(packagename=None, duration=20, attach=False, cleanup=True):
    if duration < 1:
        duration = 1

    js_code = _load_dexdump_hook_script()

    for device in get_adb_devices():
        serial = device.get_serial_no()
        eprint("Device: {} ({})".format(get_device_model(device), serial))

        target = _resolve_target_package(device, packagename)
        if target is None:
            eprint("No focused app. Specify package name.")
            continue

        eprint("Target package: {}".format(target))
        frida_device = frida.get_device(serial)

        session = None
        script = None
        pid = None

        try:
            if attach:
                eprint("Attaching to running process...")
                session = frida_device.attach(target)
            else:
                eprint("Spawning process and installing hooks...")
                pid = frida_device.spawn([target])
                session = frida_device.attach(pid)

            script = session.create_script(js_code)
            script.on("message", _message_callback)
            script.load()

            if pid is not None:
                frida_device.resume(pid)

            eprint("Collecting dex artifacts for {} seconds...".format(duration))
            time.sleep(duration)
        except Exception as err:
            eprint("Dex dump hook failed: {}".format(err))
        finally:
            try:
                if script:
                    script.unload()
            except Exception:
                pass
            try:
                if session:
                    session.detach()
            except Exception:
                pass

        internal_dump_dir = "/data/data/{}/files/dump_dex_{}".format(target, target)
        if not _exists_dir(device, internal_dump_dir, root=True):
            eprint("No dump directory found: {}".format(internal_dump_dir))
            continue

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        remote_stage = "/sdcard/fah_dexdump_{}_{}".format(_sanitize(target), stamp)
        local_base = os.path.join("fah_dexdump", _sanitize(serial))
        local_dst = os.path.join(local_base, "{}_{}".format(_sanitize(target), stamp))

        os.makedirs(local_base, exist_ok=True)

        eprint("Copying dump directory to shared storage...")
        perform_cmd(device, "rm -rf {}".format(remote_stage), root=True)
        copy_out = perform_cmd(device, "cp -r {} {}".format(internal_dump_dir, remote_stage), root=True)
        if copy_out and "No such file" in copy_out:
            eprint(copy_out.strip())
            if cleanup:
                perform_cmd(device, "rm -rf {}".format(internal_dump_dir), root=True)
            continue

        eprint("Pulling files to host: {}".format(local_dst))
        ok = _pull_with_adb(serial, remote_stage, local_dst)
        if not ok:
            eprint("adb pull failed for {}".format(remote_stage))

        if cleanup:
            eprint("Cleaning residual dump files on device...")
            perform_cmd(device, "rm -rf {}".format(remote_stage), root=True)
            perform_cmd(device, "rm -rf {}".format(internal_dump_dir), root=True)
        else:
            eprint("Keeping device files (cleanup disabled).")
