import gzip
import os
import re
import requests
from frida_android_helper.utils import *
from ppadb.device import Device as AdbDevice

PENGRIDA_INSTALL_DIR = "/data/local/tmp/"
PENGRIDA_BIN_NAME = "pengrida-server"
PENGRIDA_LATEST_RELEASE_URL = "https://api.github.com/repos/secuworm2/Pengrida/releases/latest"
PENGRIDA_TAGGED_RELEASE_URL = "https://api.github.com/repos/secuworm2/Pengrida/releases/tags/{}"

ZYGISK_GADGET_MODULE_DIR = "/data/adb/modules/zygisk_gadget/"
ZYGISK_GADGET_BIN = "/data/local/tmp/zygisk-gadget"


def _get_release(version=None):
    try:
        if version is None:
            response = requests.get(PENGRIDA_LATEST_RELEASE_URL, timeout=30)
            if response.status_code != 200:
                eprint("ERROR: Failed to query latest Pengrida release: HTTP {}".format(response.status_code))
                return None
            return response.json()

        tags_to_try = [version]
        if version.startswith("v"):
            tags_to_try.append(version[1:])
        else:
            tags_to_try.append("v{}".format(version))

        for tag in tags_to_try:
            response = requests.get(PENGRIDA_TAGGED_RELEASE_URL.format(tag), timeout=30)
            if response.status_code == 200:
                return response.json()
            if response.status_code != 404:
                eprint("ERROR: Failed to query Pengrida release '{}': HTTP {}".format(tag, response.status_code))
                return None
    except requests.RequestException as err:
        eprint("ERROR: {}".format(err))
        return None

    eprint("ERROR: Requested Pengrida version '{}' was not found.".format(version))
    return None


def download_pengrida(device: AdbDevice, version=None):
    release = _get_release(version)
    if release is None:
        return None

    arch = get_architecture(device)
    release_tag = release.get("tag_name", "latest")

    for asset in release.get("assets", []):
        release_name = asset["name"]
        if "pengrida-server" in release_name and "android-{}.gz".format(arch) in release_name:
            eprint("Downloading {}...".format(release_name))
            try:
                gz_file = requests.get(asset["browser_download_url"], timeout=60)
            except requests.RequestException as err:
                eprint("ERROR: {}".format(err))
                return None

            if gz_file.status_code != 200:
                eprint("ERROR: Failed to download {}: HTTP {}".format(release_name, gz_file.status_code))
                return None

            eprint("Extracting {}...".format(release_name))
            server_binary = gzip.decompress(gz_file.content)

            eprint("Writing {}...".format(release_name))
            with open(release_name[:-3], "wb") as f:
                f.write(server_binary)
            return release_name[:-3]

    eprint("ERROR: No pengrida-server asset found for Android architecture '{}' in release '{}'.".format(arch, release_tag))
    return None


def download_latest_pengrida(device: AdbDevice):
    return download_pengrida(device, version=None)


def launch_pengrida_server(device: AdbDevice):
    # Launch server and background it. Short timeout intentionally breaks off the command session.
    err = perform_cmd(device, "{}{} && sleep 2147483647 &".format(PENGRIDA_INSTALL_DIR, PENGRIDA_BIN_NAME), root=True, timeout=1)
    if err:
        eprint("ERROR: {}".format(err))


def start_pengrida_server():
    eprint("Starting pengrida-server")
    devices = get_adb_devices()
    for device in devices:
        eprint("Device: {} ({})".format(get_device_model(device), device.get_serial_no()))
        launch_pengrida_server(device)


def stop_pengrida_server():
    eprint("Stopping pengrida-server")
    devices = get_adb_devices()
    for device in devices:
        eprint("Device: {} ({})".format(get_device_model(device), device.get_serial_no()))
        err = perform_cmd(device, "pkill {}".format(PENGRIDA_BIN_NAME), root=True)
        if err:
            eprint("ERROR: {}".format(err))
            continue


def reboot_pengrida_server():
    eprint("Rebooting pengrida-server")
    stop_pengrida_server()
    start_pengrida_server()


def update_pengrida_server(version=None):
    if version is None:
        eprint("Updating pengrida-server to latest version")
    else:
        eprint("Updating pengrida-server to version {}".format(version))

    devices = get_adb_devices()
    for device in devices:
        eprint("Device: {} ({})".format(get_device_model(device), device.get_serial_no()))
        server_binary = download_pengrida(device, version)
        if server_binary is None:
            continue
        device.push(server_binary, "{}{}".format(PENGRIDA_INSTALL_DIR, PENGRIDA_BIN_NAME), 755)
        launch_pengrida_server(device)


def _download_gzip_asset(asset, local_name):
    eprint("Downloading {}...".format(asset["name"]))
    try:
        gz_file = requests.get(asset["browser_download_url"], timeout=60)
    except requests.RequestException as err:
        eprint("ERROR: {}".format(err))
        return None

    if gz_file.status_code != 200:
        eprint("ERROR: Failed to download {}: HTTP {}".format(asset["name"], gz_file.status_code))
        return None

    eprint("Extracting {}...".format(asset["name"]))
    with open(local_name, "wb") as f:
        f.write(gzip.decompress(gz_file.content))
    return local_name


def download_art_gadget(device: AdbDevice, version=None):
    release = _get_release(version)
    if release is None:
        return None, None

    arch = get_architecture(device)
    release_tag = release.get("tag_name", "latest")
    so_suffix = "android-{}.so.gz".format(arch)
    config_suffix = "android-{}.config.gz".format(arch)

    so_path = None
    config_path = None
    for asset in release.get("assets", []):
        name = asset["name"]
        if "pengrida-art_gadget" not in name:
            continue
        if name.endswith(so_suffix):
            so_path = _download_gzip_asset(asset, "pengrida-art-gadget-android-{}.so".format(arch))
        elif name.endswith(config_suffix):
            config_path = _download_gzip_asset(asset, "pengrida-art-gadget-android-{}.config".format(arch))

    if so_path is None or config_path is None:
        eprint("ERROR: No ART gadget assets found for Android architecture '{}' in release '{}'.".format(arch, release_tag))
        return None, None
    return so_path, config_path


def get_app_uid_and_context(device: AdbDevice, packagename: str):
    output = perform_cmd(device, "ls -laZd /data/data/{}".format(packagename), root=True)
    if not output:
        eprint("ERROR: Failed to stat /data/data/{} — is the app installed?".format(packagename))
        return None, None

    uid_match = re.search(r"u(\d+)_a(\d+)", output)
    if not uid_match:
        eprint("ERROR: Could not determine uid for {} from ls -laZ output: {}".format(packagename, output.strip()))
        return None, None
    uid = int(uid_match.group(1)) * 100000 + 10000 + int(uid_match.group(2))

    context_match = re.search(r"u:object_r:\S+:s0(?::c\d+(?:,c\d+)*)?", output)
    if not context_match:
        eprint("ERROR: Could not determine SELinux context for {} from ls -laZ output: {}".format(packagename, output.strip()))
        return None, None

    return uid, context_match.group(0)


def ensure_zygisk_gadget_enabled(device: AdbDevice, reboot_timeout: int = 180):
    disable_marker = "{}disable".format(ZYGISK_GADGET_MODULE_DIR)
    is_disabled = perform_cmd(device, "test -f {} && echo 1 || echo 0".format(disable_marker), root=True).strip()
    if is_disabled != "1":
        return True

    eprint("zygisk_gadget module is disabled — removing disable marker and rebooting to re-enable it...")
    perform_cmd(device, "rm -f {}".format(disable_marker), root=True)
    try:
        device.reboot()
    except Exception as err:
        eprint("ERROR: Failed to reboot device: {}".format(err))
        return False

    try:
        device.wait_boot_complete(timeout=reboot_timeout)
    except TimeoutError:
        eprint("ERROR: Device did not come back online within {}s; aborting.".format(reboot_timeout))
        return False

    return True


def update_pengrida_art_gadget(packagename: str, version=None, reboot_timeout: int = 180):
    if version is None:
        eprint("Installing latest pengrida ART gadget for {}".format(packagename))
    else:
        eprint("Installing pengrida ART gadget {} for {}".format(version, packagename))

    devices = get_adb_devices()
    for device in devices:
        eprint("Device: {} ({})".format(get_device_model(device), device.get_serial_no()))

        if not ensure_zygisk_gadget_enabled(device, reboot_timeout):
            continue

        uid, context = get_app_uid_and_context(device, packagename)
        if uid is None:
            continue

        so_path, config_path = download_art_gadget(device, version)
        if so_path is None or config_path is None:
            continue

        remote_so_name = os.path.basename(so_path)
        remote_config_name = os.path.basename(config_path)
        tmp_so = "{}{}".format(PENGRIDA_INSTALL_DIR, remote_so_name)
        tmp_config = "{}{}".format(PENGRIDA_INSTALL_DIR, remote_config_name)
        target_config = "/data/data/{}/{}".format(packagename, remote_config_name)

        # 2) Install the gadget .so into the zygisk_gadget module.
        device.push(so_path, tmp_so)
        perform_cmd(device, "rm -f {}*.so".format(ZYGISK_GADGET_MODULE_DIR), root=True)
        perform_cmd(device, "cp {} {}".format(tmp_so, ZYGISK_GADGET_MODULE_DIR), root=True)
        perform_cmd(device, "chmod 644 {}{}".format(ZYGISK_GADGET_MODULE_DIR, remote_so_name), root=True)

        # 3) Register the target package with the zygisk-gadget CLI, then kill it immediately.
        perform_cmd(device, "{} -p {} -d 300000 > /dev/null 2>&1 &".format(ZYGISK_GADGET_BIN, packagename), root=True, timeout=1)
        perform_cmd(device, "pkill -f zygisk-gadget", root=True)

        # 4) Place the gadget config for the target package.
        device.push(config_path, tmp_config)
        perform_cmd(device, "rm -f /data/data/{}/*.config".format(packagename), root=True)
        perform_cmd(device, "cp {} {}".format(tmp_config, target_config), root=True)
        perform_cmd(device, "chown {}:{} {}".format(uid, uid, target_config), root=True)
        perform_cmd(device, "chmod 600 {}".format(target_config), root=True)
        perform_cmd(device, "chcon {} {}".format(context, target_config), root=True)

        eprint("ART gadget installed for {} (uid={}). Launch the app to attach.".format(packagename, uid))


def clear_pengrida_art_gadget(packagename: str, reboot_timeout: int = 180):
    eprint("Restoring device from pengrida ART gadget for {}".format(packagename))

    devices = get_adb_devices()
    for device in devices:
        eprint("Device: {} ({})".format(get_device_model(device), device.get_serial_no()))

        perform_cmd(device, "touch {}disable".format(ZYGISK_GADGET_MODULE_DIR), root=True)
        perform_cmd(device, "rm -f /data/data/{0}/*gadget*.so /data/data/{0}/*gadget*.config".format(packagename), root=True)

        eprint("Rebooting device (required — zygote already loaded the module and keeps injecting until reboot)...")
        try:
            device.reboot()
        except Exception as err:
            eprint("ERROR: Failed to reboot device: {}".format(err))
            continue

        try:
            device.wait_boot_complete(timeout=reboot_timeout)
        except TimeoutError:
            eprint("ERROR: Device did not come back online within {}s; verify manually.".format(reboot_timeout))
            continue

        pid = perform_cmd(device, "pidof {}".format(packagename)).strip()
        eprint("{} pid after reboot: {}".format(packagename, pid if pid else "(not running)"))

        leftover = perform_cmd(device, "logcat -d | grep -i ZygiskGadget", root=True).strip()
        if leftover:
            eprint("WARNING: ZygiskGadget still present in logcat — restore may be incomplete:\n{}".format(leftover))
        else:
            eprint("ZygiskGadget not found in logcat — restore confirmed clean.")
