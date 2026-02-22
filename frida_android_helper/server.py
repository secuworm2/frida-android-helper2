import lzma
import requests
from frida_android_helper.utils import *
from ppadb.device import Device as AdbDevice

FRIDA_INSTALL_DIR = "/data/local/tmp/"
FRIDA_BIN_NAME = "frida-server"
FRIDA_LATEST_RELEASE_URL = "https://api.github.com/repos/frida/frida/releases/latest"
FRIDA_TAGGED_RELEASE_URL = "https://api.github.com/repos/frida/frida/releases/tags/{}"


def _get_release(version=None):
    try:
        if version is None:
            response = requests.get(FRIDA_LATEST_RELEASE_URL, timeout=30)
            if response.status_code != 200:
                eprint("ERROR: Failed to query latest Frida release: HTTP {}".format(response.status_code))
                return None
            return response.json()

        tags_to_try = [version]
        if version.startswith("v"):
            tags_to_try.append(version[1:])
        else:
            tags_to_try.append("v{}".format(version))

        for tag in tags_to_try:
            response = requests.get(FRIDA_TAGGED_RELEASE_URL.format(tag), timeout=30)
            if response.status_code == 200:
                return response.json()
            if response.status_code != 404:
                eprint("ERROR: Failed to query Frida release '{}': HTTP {}".format(tag, response.status_code))
                return None
    except requests.RequestException as err:
        eprint("ERROR: {}".format(err))
        return None

    eprint("ERROR: Requested Frida version '{}' was not found.".format(version))
    return None


def download_frida(device: AdbDevice, version=None):
    release = _get_release(version)
    if release is None:
        return None

    arch = get_architecture(device)
    release_tag = release.get("tag_name", "latest")

    for asset in release.get("assets", []):
        release_name = asset["name"]
        if "server" in release_name and "android-{}.xz".format(arch) in release_name:
            eprint("Downloading {}...".format(release_name))
            try:
                xz_file = requests.get(asset["browser_download_url"], timeout=60)
            except requests.RequestException as err:
                eprint("ERROR: {}".format(err))
                return None

            if xz_file.status_code != 200:
                eprint("ERROR: Failed to download {}: HTTP {}".format(release_name, xz_file.status_code))
                return None

            eprint("Extracting {}...".format(release_name))
            server_binary = lzma.decompress(xz_file.content)

            eprint("Writing {}...".format(release_name))
            with open(release_name[:-3], "wb") as f:
                f.write(server_binary)
            return release_name[:-3]

    eprint("ERROR: No frida-server asset found for Android architecture '{}' in release '{}'.".format(arch, release_tag))
    return None


def download_latest_frida(device: AdbDevice):
    return download_frida(device, version=None)


def launch_frida_server(device: AdbDevice):
    # Launch server and background it. Short timeout intentionally breaks off the command session.
    err = perform_cmd(device, "{}{} && sleep 2147483647 &".format(FRIDA_INSTALL_DIR, FRIDA_BIN_NAME), root=True, timeout=1)
    if err:
        eprint("ERROR: {}".format(err))


def start_server():
    eprint("Starting frida-server")
    devices = get_adb_devices()
    for device in devices:
        eprint("Device: {} ({})".format(get_device_model(device), device.get_serial_no()))
        launch_frida_server(device)


def stop_server():
    eprint("Stopping frida-server")
    devices = get_adb_devices()
    for device in devices:
        eprint("Device: {} ({})".format(get_device_model(device), device.get_serial_no()))
        err = perform_cmd(device, "pkill frida-server", root=True)
        if err:
            eprint("ERROR: {}".format(err))
            continue


def reboot_server():
    eprint("Rebooting frida-server")
    stop_server()
    start_server()


def update_server(version=None):
    if version is None:
        eprint("Updating frida-server to latest version")
    else:
        eprint("Updating frida-server to version {}".format(version))

    devices = get_adb_devices()
    for device in devices:
        eprint("Device: {} ({})".format(get_device_model(device), device.get_serial_no()))
        server_binary = download_frida(device, version)
        if server_binary is None:
            continue
        device.push(server_binary, "{}{}".format(FRIDA_INSTALL_DIR, FRIDA_BIN_NAME), 755)
        launch_frida_server(device)
