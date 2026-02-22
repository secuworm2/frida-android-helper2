from frida_android_helper.utils import *


# Enabling and disabling is powered by https://stackoverflow.com/a/47476009
PROXY_KEYS = (
    "http_proxy",
    "global_http_proxy_host",
    "global_http_proxy_port",
    "global_http_proxy_exclusion_list",
    "global_proxy_pac_url",
)


def _print_proxy_state(device):
    for key in PROXY_KEYS:
        value = device.shell("settings get global {}".format(key)).strip()
        eprint("  {} => {}".format(key, value))


def enable_proxy(host=None, port="8080"):
    if host is None:
        host = get_ip_address()
        if host == "127.0.0.1":
            eprint("Can't determine IP address. Provide an IP or connect your PC to the internet.")
            return
    if not port.isdigit():  # Just in case...
        port = 8080

    eprint("Enabling Android proxy...")
    for device in get_adb_devices():
        eprint("Device: {} ({})".format(get_device_model(device), device.get_serial_no()))
        device.shell("settings put global http_proxy {}:{}".format(host, port))
        result = device.shell("settings get global http_proxy")
        eprint("settings put global http_proxy {}:{} => {}".format(host, port, result.strip()))


def disable_proxy():
    eprint("Disabling Android proxy...")
    for device in get_adb_devices():
        eprint("Device: {} ({})".format(get_device_model(device), device.get_serial_no()))

        # Some Android builds keep state unless :0 is applied before cleanup.
        result = device.shell("settings put global http_proxy :0")
        eprint("settings put global http_proxy :0 -> {}".format(result.strip()))

        for key in PROXY_KEYS:
            result = device.shell("settings delete global {}".format(key))
            eprint("settings delete global {} -> {}".format(key, result.strip()))

        # Notify framework to reload proxy state.
        perform_cmd(device, "am broadcast -a android.intent.action.PROXY_CHANGE", root=True)
        eprint("Sent PROXY_CHANGE broadcast.")

        # Helpful warning when reverse tethering rules are still active.
        nat_rules = perform_cmd(device, "iptables -t nat -S", root=True)
        if "DNAT" in nat_rules and "127.0.0.1" in nat_rules:
            eprint("Warning: DNAT rules to 127.0.0.1 still exist (rproxy residue).")
            eprint("Run 'fah rproxy disable' to fully restore network routing.")

        eprint("Current proxy keys:")
        _print_proxy_state(device)


def get_proxy():
    eprint("Retrieving Android proxy settings...")
    for device in get_adb_devices():
        eprint("Device: {} ({})".format(get_device_model(device), device.get_serial_no()))
        _print_proxy_state(device)
