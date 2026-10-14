import os
import re
import tarfile
from datetime import datetime
from frida_android_helper.utils import *

# Characters that are illegal in Windows file names. adb pull recreates the
# device file names verbatim on the host, so names such as Firebase Remote
# Config's "frc_1:...:android:..._firebase_settings.xml" (which contain colons)
# make the pull fail on Windows with "No such file or directory".
_ILLEGAL_WIN_CHARS = re.compile(r'[<>:"|?*]')


def _sanitize_path(name):
    # Sanitize each path segment so the snapshot can be written on any host.
    parts = [_ILLEGAL_WIN_CHARS.sub("_", p)
             for p in name.replace("\\", "/").split("/") if p not in ("", ".", "..")]
    return os.path.join(*parts) if parts else ""


def _download_snapshot(device, directory_name):
    # Stream the directory as a tar and extract it locally, sanitizing each
    # path. Plain `adb pull` recreates device file names verbatim, which
    # fails on Windows for names containing illegal characters (e.g. the
    # colons in Firebase Remote Config files). See issue linked above:
    # https://github.com/Swind/pure-python-adb/issues/28
    proc = subprocess.Popen(
        ["adb", "-s", device.get_serial_no(), "exec-out",
         "tar", "-C", "/sdcard/Download", "-cf", "-", directory_name],
        stdout=subprocess.PIPE)
    ok = True
    try:
        with tarfile.open(fileobj=proc.stdout, mode="r|") as tar:
            for member in tar:
                safe = _sanitize_path(member.name)
                if not safe:
                    continue
                member.name = safe
                if member.islnk() or member.issym():
                    member.linkname = _sanitize_path(member.linkname)
                if (member.isfile() or member.islnk() or member.issym()) and os.path.exists(safe):
                    eprint("⚠️  Name collision after sanitizing, overwriting {}".format(safe))
                try:
                    tar.extract(member)
                except (OSError, KeyError) as e:
                    eprint("⚠️  Skipped {}: {}".format(member.name, e))
    except (tarfile.TarError, OSError) as e:
        eprint("❌ Failed to extract snapshot: {}".format(e))
        ok = False
    finally:
        proc.stdout.close()
        proc.wait()
    if proc.returncode != 0:
        eprint("❌ tar on device exited with {}; transfer may be incomplete".format(proc.returncode))
        ok = False
    return ok


def take_snapshot(packagename=None):
    eprint("⚡️ Taking a snapshot...")
    for device in get_adb_devices():
        eprint("📲 Device: {} ({})".format(get_device_model(device), device.get_serial_no()))
        pkg = packagename
        if pkg is None:  # get
            pkg = get_current_app_focus(device)
            if pkg is None:
                eprint("❌️ No app is open, specify package name.")
                continue

        directory_name = "{}_{}".format(pkg, datetime.now().strftime("%Y.%m.%d_%H.%M.%S"))

        eprint("🔥 Copying from /data/data/{} to /sdcard/Download/{}...".format(pkg, directory_name))
        err = perform_cmd(device, "cp -Lpr /data/data/{} /sdcard/Download/{}".format(pkg, directory_name), root=True)
        if err:
            eprint("❌ {}".format(err))
            continue

        eprint("🔥 Downloading from /sdcard/Download/{}...".format(directory_name))
        ok = _download_snapshot(device, directory_name)

        if not ok:
            eprint("⚠️  Leaving /sdcard/Download/{} on the device so no data is lost.".format(directory_name))
            continue

        eprint("🔥 Cleaning up /sdcard/Download/{}...".format(directory_name))
        perform_cmd(device, "rm -rf /sdcard/Download/{}".format(directory_name))
