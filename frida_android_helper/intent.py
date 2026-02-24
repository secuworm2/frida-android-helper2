import logging
import os
import tempfile

from frida_android_helper.utils import *

try:
    from androguard.core.apk import APK
except ImportError:
    # Backward compatibility with older androguard layouts.
    from androguard.core.bytecodes.apk import APK

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
COMPONENT_TAGS = {
    "activity": ("activity", "activity-alias"),
    "service": ("service",),
    "receiver": ("receiver",),
    "provider": ("provider",),
}


def _strip_xml_namespace(tag):
    if not isinstance(tag, str):
        return None
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _merge_actions(existing_actions, new_actions):
    merged = []
    seen = set()
    for action in (existing_actions or []) + (new_actions or []):
        if not action or action in seen:
            continue
        seen.add(action)
        merged.append(action)
    return merged


def _extract_receiver_actions(receiver_node):
    actions = []
    for child in receiver_node:
        child_tag = _strip_xml_namespace(child.tag)
        if child_tag != "intent-filter":
            continue
        for filter_item in child:
            filter_tag = _strip_xml_namespace(filter_item.tag)
            if filter_tag != "action":
                continue
            action_name = filter_item.get("{}name".format(ANDROID_NS)) or filter_item.get("name")
            if action_name:
                actions.append(action_name)
    return _merge_actions([], actions)


def _silence_androguard_logs():
    logging.getLogger("androguard").setLevel(logging.WARNING)
    try:
        from loguru import logger
        logger.disable("androguard")
    except Exception:
        pass


_silence_androguard_logs()


def _normalize_component_name(packagename, component_name):
    if component_name.startswith("."):
        fqcn = "{}{}".format(packagename, component_name)
    elif "." in component_name:
        fqcn = component_name
    else:
        fqcn = "{}.{}".format(packagename, component_name)
    return "{}/{}".format(packagename, fqcn)


def _get_apk_paths(device, packagename):
    result = perform_cmd(device, "pm path {}".format(packagename))
    paths = []
    for line in result.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            paths.append(line[len("package:"):])
    return paths


def _extract_components_from_manifest(apk_path, fallback_packagename, component_type):
    tags = COMPONENT_TAGS.get(component_type)
    if not tags:
        return []

    try:
        apk = APK(apk_path)
    except Exception as err:
        eprint("Failed to parse APK manifest {}: {}".format(apk_path, err))
        return None

    try:
        manifest = apk.get_android_manifest_xml()
    except Exception as err:
        eprint("Failed to read AndroidManifest.xml from {}: {}".format(apk_path, err))
        return None

    if manifest is None:
        eprint("AndroidManifest.xml not found in {}.".format(apk_path))
        return None

    package_name = apk.get_package() or fallback_packagename
    components = []
    seen_entries = {}

    for node in manifest.iter():
        tag = _strip_xml_namespace(node.tag)
        if tag not in tags:
            continue

        component_name = node.get("{}name".format(ANDROID_NS)) or node.get("name")
        if not component_name:
            continue

        normalized_component = _normalize_component_name(package_name, component_name)
        if component_type != "provider":
            key = (normalized_component, None)
            receiver_actions = _extract_receiver_actions(node) if component_type == "receiver" else []
            existing_entry = seen_entries.get(key)
            if existing_entry is not None:
                if component_type == "receiver":
                    existing_entry["actions"] = _merge_actions(existing_entry.get("actions"), receiver_actions)
                continue
            entry = {
                "component": normalized_component,
                "authority": None,
                "actions": receiver_actions,
            }
            components.append(entry)
            seen_entries[key] = entry
            continue

        authorities_value = node.get("{}authorities".format(ANDROID_NS)) or node.get("authorities") or ""
        authorities = [a.strip() for a in authorities_value.split(";") if a.strip()]
        if not authorities:
            key = (normalized_component, None)
            if key not in seen_entries:
                entry = {
                    "component": normalized_component,
                    "authority": None,
                    "actions": [],
                }
                components.append(entry)
                seen_entries[key] = entry
            continue

        for authority in authorities:
            key = (normalized_component, authority)
            if key in seen_entries:
                continue
            entry = {
                "component": normalized_component,
                "authority": authority,
                "actions": [],
            }
            components.append(entry)
            seen_entries[key] = entry

    return components


def _collect_components_for_device(device, packagename, component_type):
    apk_paths = _get_apk_paths(device, packagename)
    if not apk_paths:
        eprint("Failed to locate APK path for {}.".format(packagename))
        return []

    all_components = []
    with tempfile.TemporaryDirectory(prefix="fah_manifest_") as temp_dir:
        for index, apk_path in enumerate(apk_paths):
            local_apk = os.path.join(temp_dir, "apk_{}.apk".format(index))
            try:
                device.pull(apk_path, local_apk)
            except Exception as err:
                eprint("Failed to pull APK {}: {}".format(apk_path, err))
                continue

            components = _extract_components_from_manifest(local_apk, packagename, component_type)
            if components is None:
                continue
            all_components.extend(components)

    deduped = []
    deduped_by_key = {}
    for component in all_components:
        key = (component.get("component"), component.get("authority"))
        existing_entry = deduped_by_key.get(key)
        if existing_entry is not None:
            existing_entry["actions"] = _merge_actions(existing_entry.get("actions"), component.get("actions"))
            continue
        entry = {
            "component": component.get("component"),
            "authority": component.get("authority"),
            "actions": _merge_actions([], component.get("actions")),
        }
        deduped_by_key[key] = entry
        deduped.append(entry)
    return deduped


def _resolve_target_component(packagename, components, target, component_type):
    if target is None:
        return None

    if target.isdigit():
        index = int(target)
        if index < 1 or index > len(components):
            eprint("Invalid {} index: {} (valid range: 1-{})".format(component_type, index, len(components)))
            return None
        return components[index - 1]

    if component_type == "provider":
        provider_authority = target
        if provider_authority.startswith("content://"):
            provider_authority = provider_authority[len("content://"):]
        provider_authority = provider_authority.split("/", 1)[0]
        for entry in components:
            if entry.get("authority") == provider_authority:
                return entry

    if "/" in target:
        if target.startswith("{}/".format(packagename)):
            normalized_target = target
            for entry in components:
                if entry.get("component") == normalized_target:
                    return entry
            return {
                "component": normalized_target,
                "authority": None,
                "actions": [],
            }
        eprint("Target component must start with '{}/'.".format(packagename))
        return None

    normalized_target = _normalize_component_name(packagename, target)
    for entry in components:
        if entry.get("component") == normalized_target:
            return entry

    return {
        "component": normalized_target,
        "authority": None,
        "actions": [],
    }


def _format_component(entry, component_type):
    component = entry.get("component")
    authority = entry.get("authority")
    if component_type == "provider":
        if authority:
            return "{} (authority={})".format(component, authority)
        return "{} (authority=<none>)".format(component)
    if component_type == "receiver":
        actions = entry.get("actions") or []
        if actions:
            return "{} (actions={})".format(component, ", ".join(actions))
        return "{} (actions=<none>)".format(component)
    return component


def _build_manual_commands(entry, component_type):
    component = entry.get("component")
    authority = entry.get("authority")
    actions = entry.get("actions") or []

    if component_type == "activity":
        return ["am start -n {}".format(component)]
    if component_type == "service":
        return ["am startservice -n {}".format(component)]
    if component_type == "receiver":
        if not actions:
            return ["am broadcast -n {} -a fah.intent.TEST".format(component)]
        return ["am broadcast -n {} -a {}".format(component, action) for action in actions]
    if component_type == "provider":
        if not authority:
            return []
        return ["content query --uri content://{}".format(authority)]
    return []


def _print_manual_commands(device, components, component_type):
    serial_no = device.get_serial_no()
    eprint("Manual commands for {} on device {} (run inside adb shell):".format(component_type, serial_no))
    for entry in components:
        commands = _build_manual_commands(entry, component_type)
        if not commands:
            eprint("Skipping {} (authority missing)".format(_format_component(entry, component_type)))
            continue
        for cmd in commands:
            print(cmd)


def _start_component(device, entry, component_type):
    component = entry.get("component")
    authority = entry.get("authority")
    actions = entry.get("actions") or []
    if component_type == "activity":
        eprint("Starting activity {}...".format(component))
        cmd = "am start -n {}".format(component)
    elif component_type == "service":
        eprint("Starting service {}...".format(component))
        cmd = "am startservice -n {}".format(component)
    elif component_type == "receiver":
        if actions:
            action = actions[0]
            if len(actions) > 1:
                eprint("Receiver has {} actions, using first one: {}".format(len(actions), action))
            eprint("Broadcasting receiver {} with action {}...".format(component, action))
            cmd = "am broadcast -n {} -a {}".format(component, action)
        else:
            eprint("No manifest action found, using fallback action fah.intent.TEST for {}...".format(component))
            cmd = "am broadcast -n {} -a fah.intent.TEST".format(component)
    elif component_type == "provider":
        if not authority:
            eprint("Provider '{}' has no authority, cannot query it directly.".format(component))
            return
        eprint("Querying provider {} (authority={})...".format(component, authority))
        cmd = "content query --uri content://{}".format(authority)
    else:
        eprint("Unsupported component type: {}".format(component_type))
        return

    output = perform_cmd(device, cmd)
    denied_markers = (
        "Permission Denial",
        "not exported",
        "java.lang.SecurityException",
    )
    if any(marker in output for marker in denied_markers):
        eprint("Permission denied, retrying with root...")
        output = perform_cmd(device, cmd, root=True)
    if output:
        print(output.strip())


def list_components(component_type, packagename=None, target=None):
    for device in get_adb_devices():
        eprint("Device: {} ({})".format(get_device_model(device), device.get_serial_no()))
        current_package = packagename or get_current_app_focus(device)
        if current_package is None:
            eprint("No app is open, specify package name.")
            continue

        eprint("Listing {}s for {}...".format(component_type, current_package))
        components = _collect_components_for_device(device, current_package, component_type)
        if not components:
            eprint("No {}s found for {}.".format(component_type, current_package))
            continue

        if isinstance(target, str) and target.lower() == "manual":
            _print_manual_commands(device, components, component_type)
            continue

        if target is None:
            for index, component in enumerate(components, start=1):
                print("[{}] {}".format(index, _format_component(component, component_type)))
            continue

        component = _resolve_target_component(current_package, components, target, component_type)
        if component is None:
            continue
        _start_component(device, component, component_type)


def list_activities(packagename=None, target=None):
    list_components("activity", packagename, target)


def list_services(packagename=None, target=None):
    list_components("service", packagename, target)


def list_receivers(packagename=None, target=None):
    list_components("receiver", packagename, target)


def list_providers(packagename=None, target=None):
    list_components("provider", packagename, target)
