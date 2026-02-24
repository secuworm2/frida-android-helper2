# Frida Android Helper

![preview](preview.png?raw=true)

Several handy commands to facilitate common Android pentesting tasks.

It uses `pure-python-adb` to interface with the ADB server.


## Prerequisites
- Python 3
- ADB
- Rooted Android phone


## Installation
1. Clone the repository: `git clone https://github.com/secuworm2/frida-android-helper2`
2. Install with pip: `python -m pip install . --no-cache-dir`
3. (Optional) Editable install for development: `python -m pip install -e . --no-cache-dir`


## Usage

Commands are self explanatory. Ask for help `fah --help`.


### Frida-server management

| Command | Description |
| --- | --- |
| `fah server start` | Start frida-server on device. |
| `fah server stop` | Stop frida-server on device. |
| `fah server reboot` | Reboot frida-server on device. |
| `fah server update` | Install the latest frida-server release from GitHub. |
| `fah server update 17.2.1` | Install a specific frida-server version. |


### Android proxy configuration

| Command | Description |
| --- | --- |
| `fah proxy` | Enable proxy with auto-detected host IP and default port `8080`. |
| `fah proxy enable` | Same as `fah proxy`. |
| `fah proxy enable 192.168.137.137` | Enable proxy with custom host IP and default port `8080`. |
| `fah proxy enable 192.168.137.137 8888` | Enable proxy with custom host and port. |
| `fah proxy disable` | Disable global Android proxy settings. |
| `fah proxy get` | Print current proxy-related settings. |


### Android proxy via reverse tethering configuration
Route traffic through `adb reverse` + iptables DNAT rules.

| Command | Description |
| --- | --- |
| `fah rproxy` | Enable reverse-tether proxy on default port `8844`. |
| `fah rproxy enable` | Same as `fah rproxy`. |
| `fah rproxy enable 8888` | Enable reverse-tether proxy on a custom port. |
| `fah rproxy disable` | Disable reverse-tether proxy on default port `8844`. |
| `fah rproxy disable 8888` | Disable reverse-tether proxy on a custom port. |

Recommended flow:
1. Connect device via USB.
2. Start intercepting proxy (e.g. Burp) in transparent mode.
3. Connect device to any Wi-Fi network.


### Android screenshot
| Command | Description |
| --- | --- |
| `fah screen` | Save screenshot as `deviceID_%Y.%m.%d_%H.%M.%S.png`. |
| `fah screen filename` | Save screenshot as `deviceID_filename.png`. |


### Android disk snapshot
| Command | Description |
| --- | --- |
| `fah snap` | Snapshot current focused app data directory. |
| `fah snap com.example.app` | Snapshot specified app data directory. |


### Android certificate creation & installation for mitm purposes
| Command | Description |
| --- | --- |
| `fah cert` | Generate custom CA certificate for MITM use. |
| `fah cert generate` | Same as `fah cert`. |
| `fah cert install` | Install a certificate on device. |
| `fah cert setup` | Generate and install certificate in one step. |

### Android app
| Command | Description |
| --- | --- |
| `fah app` | Download the currently focused app APK(s). |
| `fah app dl` | Same as `fah app`. |
| `fah app dl <filter>` | Find packages by filter and download APK(s). |
| `fah app list` | List installed apps in `name (package) [pid]` format. |
| `fah app list <filter>` | Filter app list by app name or package. |
| `fah app start <pkg>` | Start app launcher activity. |
| `fah app stop <pkg>` | Force-stop app process. |
| `fah app clear <pkg>` | Clear app data (`pm clear`). |

### Android intents
Syntax: `fah intent <type> [package] [target]`

Arguments:
| Name | Meaning |
| --- | --- |
| `<type>` | `activity` \| `service` \| `receiver` \| `provider` |
| `[package]` | Optional package name. If omitted, uses focused app. |
| `[target]` | Optional target: `<index>`, `<component>`, or `manual`. |

Component commands:
| Type | List | Run by index | Manual output |
| --- | --- | --- | --- |
| `activity` | `fah intent activity com.example.app` | `fah intent activity com.example.app 7` | `fah intent activity com.example.app manual` |
| `service` | `fah intent service com.example.app` | `fah intent service com.example.app 3` | `fah intent service com.example.app manual` |
| `receiver` | `fah intent receiver com.example.app` | `fah intent receiver com.example.app 2` | `fah intent receiver com.example.app manual` |
| `provider` | `fah intent provider com.example.app` | `fah intent provider com.example.app 1` | `fah intent provider com.example.app manual` |

Notes:
- Receiver actions are parsed from each manifest `intent-filter` and shown in list output.
- Receiver `manual` output prints one `am broadcast` command per discovered action.
- If no manifest action exists for a receiver, FAH falls back to `-a fah.intent.TEST`.

### Android network capture
| Command | Description |
| --- | --- |
| `fah netcap start` | Start background `tcpdump` capture on device (`-i any`). |
| `fah netcap start <pkg>` | Start capture with package UID filter (if supported by tcpdump). |
| `fah netcap stop` | Stop capture and pull `.pcap` to current directory. |

Requirements:
- Rooted device.
- `tcpdump` available on device (`PATH` or `/data/local/tmp/tcpdump`).

### Android clipboard
| Command | Description |
| --- | --- |
| `fah clip` | Show Android clipboard content. |
| `fah clip copy` | Same as `fah clip`. |
| `fah clip paste foo bar` | Set clipboard text to `foo bar`. |

### Runtime dex dump
ART `DefineClass` hook + auto collection + device cleanup.
Reference: inspired by [frida_dump](https://github.com/lasting-yang/frida_dump).

| Command | Description |
| --- | --- |
| `fah dexdump com.example.app` | Spawn app, hook ART DefineClass, dump payloads, pull to host, cleanup device files. |
| `fah dexdump com.example.app --duration 45` | Same, but keep hooks attached for 45 seconds. |
| `fah dexdump com.example.app --attach` | Attach to a running process instead of spawn. |
| `fah dexdump com.example.app --keep-device-files` | Pull to host but keep dump artifacts on device. |

Host output path:
- `./fah_dexdump/<deviceSerial>/<package>_<timestamp>/`

## Ideas & bugs
Ideas and bug reports are welcome! 
