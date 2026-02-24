import argparse

from frida_android_helper.screen import *
from frida_android_helper.server import *
from frida_android_helper.proxy import *
from frida_android_helper.rproxy import *
from frida_android_helper.snap import *
from frida_android_helper.cert import *
from frida_android_helper.app import *
from frida_android_helper.clip import *
from frida_android_helper.input import *
from frida_android_helper.intent import *
from frida_android_helper.netcap import *
from frida_android_helper.dexdump import *

def main():
    arg_parser = argparse.ArgumentParser(
        prog="fah",
        description="Frida Android Helper",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  fah app start com.example.app\n"
            "  fah app clear com.example.app\n"
            "  fah intent activity com.example.app manual\n"
            "  fah server update 17.2.1"
        ),
    )
    subparsers = arg_parser.add_subparsers(dest="func", title="commands", metavar="command")

    server_group = subparsers.add_parser("server", help="Manage Frida server")
    server_group.add_argument("action", type=str, help="Frida server on Android", nargs="?",
                              choices=("start", "stop", "reboot", "update"))
    server_group.add_argument("version", type=str, help="Frida version used by update (e.g. 17.2.1)", nargs="?")

    proxy_group = subparsers.add_parser("proxy", help="Configure Android proxy")
    proxy_group.add_argument("action", metavar="enable", type=str, help="Enable Android proxy", nargs="*", default=["set"])
    proxy_group.add_argument("disable", type=str, help="Disable Android proxy", nargs="?")
    proxy_group.add_argument("get", type=str, help="Get Android proxy settings", nargs="?")

    rproxy_group = subparsers.add_parser("rproxy", help="Configure Android proxy via reverse tethering")
    rproxy_group.add_argument("action", metavar="enable", type=str, help="Enable Android proxy via reverse tethering", nargs="*", default=["set"])
    rproxy_group.add_argument("disable", type=str, help="Disable Android proxy via reverse tethering", nargs="?")

    screen_group = subparsers.add_parser("screen", help="Take screenshot for evidence")
    screen_group.add_argument("action", metavar="filename", type=str, help="Specify filename", nargs="?", default=None)

    snap_group = subparsers.add_parser("snap", help="Make snapshots of data on disk")
    snap_group.add_argument("action", metavar="packagename", type=str, help="Specify packagename", nargs="?", default=None)

    cert_group = subparsers.add_parser("cert", help="Certificate creation & installation for mitm purposes")
    cert_group.add_argument("action", metavar="generate", type=str, help="Generate certificate", nargs="*", default=["generate"])
    cert_group.add_argument("install", type=str, help="Install a certificate", nargs="?")
    cert_group.add_argument("setup", type=str, help="Generate & install certificate", nargs="?")

    app_group = subparsers.add_parser(
        "app",
        help="App lifecycle and APK download helpers",
        description="Manage app lifecycle and download APK files from device.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  fah app dl\n"
            "  fah app dl sshdroid\n"
            "  fah app list hana\n"
            "  fah app start com.example.app\n"
            "  fah app stop com.example.app\n"
            "  fah app clear com.example.app"
        ),
    )
    app_group.add_argument(
        "action",
        type=str,
        nargs="?",
        default="dl",
        choices=("dl", "list", "start", "stop", "clear"))
    app_group.add_argument(
        "target",
        type=str,
        nargs="?",
        default=None,
        help=(
            "Target package or filter.\n"
            "  dl      : package filter (optional)\n"
            "  list    : app name/package filter (optional)\n"
            "  start/stop/clear : package name (recommended)"
        ),
    )

    clip_group = subparsers.add_parser("clip", help="Manage Android's clipboard")
    clip_group.add_argument("action", metavar="copy", type=str, help="Copy from Android's clipboard", nargs="*", default=["copy"])
    clip_group.add_argument("paste", type=str, help="Paste to Android's clipboard", nargs="?")

    input_group = subparsers.add_parser("input", help="Input manipulation")
    input_group.add_argument("action", metavar="text", type=str, help="Write to input", nargs="*", default=None)

    intent_group = subparsers.add_parser(
        "intent",
        help="Component listing and quick trigger helpers",
        description="List or trigger Android components parsed from AndroidManifest.xml.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  fah intent activity com.example.app\n"
            "  fah intent activity com.example.app 7\n"
            "  fah intent activity com.example.app manual\n"
            "  fah intent service com.example.app\n"
            "  fah intent receiver com.example.app 2\n"
            "  fah intent provider com.example.app 1"
        ),
    )
    intent_subparsers = intent_group.add_subparsers(dest="intent_action", title="intent commands", metavar="intent_command")

    common_target_help = (
        "Optional target:\n"
        "  <index>      run selected entry\n"
        "  <component>  run by full/short component name\n"
        "  manual       print shell-ready commands"
    )

    intent_activity = intent_subparsers.add_parser(
        "activity",
        help="List/trigger activities",
        description="List or trigger activities.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  fah intent activity com.example.app\n"
            "  fah intent activity com.example.app 7\n"
            "  fah intent activity com.example.app manual"
        ),
    )
    intent_activity.add_argument("packagename", type=str, help="Package name (optional: uses focused app)", nargs="?", default=None)
    intent_activity.add_argument("target", type=str, help=common_target_help, nargs="?", default=None)

    intent_service = intent_subparsers.add_parser(
        "service",
        help="List/trigger services",
        description="List or trigger services.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  fah intent service com.example.app\n"
            "  fah intent service com.example.app 3\n"
            "  fah intent service com.example.app manual"
        ),
    )
    intent_service.add_argument("packagename", type=str, help="Package name (optional: uses focused app)", nargs="?", default=None)
    intent_service.add_argument("target", type=str, help=common_target_help, nargs="?", default=None)

    intent_receiver = intent_subparsers.add_parser(
        "receiver",
        help="List/trigger receivers",
        description="List or trigger receivers.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  fah intent receiver com.example.app\n"
            "  fah intent receiver com.example.app 2\n"
            "  fah intent receiver com.example.app manual"
        ),
    )
    intent_receiver.add_argument("packagename", type=str, help="Package name (optional: uses focused app)", nargs="?", default=None)
    intent_receiver.add_argument("target", type=str, help=common_target_help, nargs="?", default=None)

    intent_provider = intent_subparsers.add_parser(
        "provider",
        help="List/trigger providers",
        description="List or trigger providers.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  fah intent provider com.example.app\n"
            "  fah intent provider com.example.app 1\n"
            "  fah intent provider com.example.app manual"
        ),
    )
    intent_provider.add_argument("packagename", type=str, help="Package name (optional: uses focused app)", nargs="?", default=None)
    intent_provider.add_argument("target", type=str, help=common_target_help, nargs="?", default=None)

    netcap_group = subparsers.add_parser(
        "netcap",
        help="Capture device network traffic with tcpdump",
        description="Start/stop tcpdump capture on device and pull the resulting pcap file.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  fah netcap start\n"
            "  fah netcap start com.example.app\n"
            "  fah netcap stop"
        ),
    )
    netcap_group.add_argument(
        "action",
        type=str,
        nargs="?",
        default="start",
        choices=("start", "stop"),
    )
    netcap_group.add_argument(
        "target",
        type=str,
        nargs="?",
        default=None,
        help="Optional package name for start action (captures only that app's UID traffic).",
    )

    dexdump_group = subparsers.add_parser(
        "dexdump",
        help="Dump runtime-loaded dex and collect to host",
        description="Hook ART DefineClass, dump runtime dex payloads, pull them to host, then optionally clean device artifacts.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  fah dexdump com.example.app\n"
            "  fah dexdump com.example.app --duration 45\n"
            "  fah dexdump com.example.app --attach\n"
            "  fah dexdump com.example.app --keep-device-files"
        ),
    )
    dexdump_group.add_argument(
        "packagename",
        type=str,
        nargs="?",
        default=None,
        help="Target package name (optional: uses currently focused app).",
    )
    dexdump_group.add_argument(
        "--duration",
        type=int,
        default=20,
        help="Seconds to keep hooks attached while app loads code (default: 20).",
    )
    dexdump_group.add_argument(
        "--attach",
        action="store_true",
        help="Attach to an already running app instead of spawn.",
    )
    dexdump_group.add_argument(
        "--keep-device-files",
        action="store_true",
        help="Do not delete /data/data/<pkg>/files/dump_dex_<pkg> and /sdcard staging folder.",
    )

    args = arg_parser.parse_args()
    if not args.func:
        arg_parser.print_help()

    if args.func == "server":
        if args.action == "update":
            update_server(args.version)
        else:
            server_route = {
                "start": start_server,
                "stop": stop_server,
                "reboot": reboot_server,
            }
            server_route.get(args.action, start_server)()
    elif args.func == "proxy":
        proxy_route = {
            "enable": enable_proxy,
            "disable": disable_proxy,
            "get": get_proxy
        }
        proxy_route.get(args.action[0], enable_proxy)(*args.action[1:3])
    elif args.func == "screen":
        take_screenshot(args.action)
    elif args.func == "snap":
        take_snapshot(args.action)
    elif args.func == "cert":
        cert_route = {
            "generate": generate_certificate,
            "install": install_certificate,
            "setup": setup_certificate,
        }
        cert_route.get(args.action[0], generate_certificate)(*args.action[1:2])
    elif args.func == "app":
        app_route = {
            "dl": download_app,
            "list": list_apps,
            "start": start_app,
            "stop": stop_app,
            "clear": clear_app,
        }
        app_route.get(args.action, download_app)(args.target)
    elif args.func == "clip":
        if args.action[0] == "copy":
            copy_from_clipboard()
        elif args.action[0] == "paste":
            paste_to_clipboard(" ".join(args.action[1:]))
        else:
            paste_to_clipboard(" ".join(args.action))
    elif args.func == "rproxy":
        rproxy_route = {
            "enable": enable_rproxy,
            "disable": disable_rproxy
        }
        rproxy_route.get(args.action[0], enable_rproxy)(*args.action[1:2])
    elif args.func == "input":
        if args.action[0] == "text":
            input_text(" ".join(args.action[1:]))
    elif args.func == "intent":
        if not args.intent_action:
            intent_group.print_help()
        elif args.intent_action == "activity":
            list_activities(args.packagename, args.target)
        elif args.intent_action == "service":
            list_services(args.packagename, args.target)
        elif args.intent_action == "receiver":
            list_receivers(args.packagename, args.target)
        elif args.intent_action == "provider":
            list_providers(args.packagename, args.target)
    elif args.func == "netcap":
        if args.action == "start":
            start_netcap(args.target)
        elif args.action == "stop":
            stop_netcap()
    elif args.func == "dexdump":
        run_dexdump(
            packagename=args.packagename,
            duration=args.duration,
            attach=args.attach,
            cleanup=not args.keep_device_files,
        )
    # print(args) # debugging purposes


if __name__ == "__main__":
    main()
