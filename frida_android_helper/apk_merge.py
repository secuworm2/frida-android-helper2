import copy
import os
import shutil
import subprocess
import uuid
import xml.etree.ElementTree as ET

import appdirs

try:
    from androguard.core.apk import APK
except ImportError:
    from androguard.core.bytecodes.apk import APK


ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
SPLIT_MANIFEST_ATTRS = (
    "{}isSplitRequired".format(ANDROID_NS),
    "{}requiredSplitTypes".format(ANDROID_NS),
    "{}splitTypes".format(ANDROID_NS),
    "split",
    "configForSplit",
)
SPLIT_METADATA_NAMES = {
    "com.android.vending.splits.required",
    "com.android.vending.splits",
    "com.android.vending.derived.apk.id",
}
REMOVABLE_METADATA_NAMES = SPLIT_METADATA_NAMES | {
    "com.android.stamp.source",
    "com.android.stamp.type",
}
TOOLS_DIR = os.path.join(os.path.dirname(__file__), "tools")
APKTOOL_JAR = os.path.join(TOOLS_DIR, "apktool.jar")
APKTOOL_FALLBACK_JAR = os.path.join(TOOLS_DIR, "apktool_2.12.0.jar")
APKSIGNER_JAR = os.path.join(TOOLS_DIR, "apksigner.jar")
ZIPALIGN_EXE = os.path.join(TOOLS_DIR, "zipalign.exe")
SIGNING_KEY = os.path.join(TOOLS_DIR, "testkey.pk8")
SIGNING_CERT = os.path.join(TOOLS_DIR, "testkey.x509.pem")
SKIP_TOP_LEVEL = {"AndroidManifest.xml", "apktool.yml", "build", "dist", "original"}
XML_DECLARATION = "<?xml version='1.0' encoding='utf-8'?>\n"
SIGNATURE_META_FILENAMES = {"MANIFEST.MF"}
SIGNATURE_META_SUFFIXES = (".SF", ".RSA", ".DSA", ".EC")

ET.register_namespace("android", "http://schemas.android.com/apk/res/android")


class ApkMergeError(RuntimeError):
    pass


def merge_split_apks(apk_paths, package_name, output_dir):
    split_infos = [_read_apk_info(apk_path) for apk_path in apk_paths]
    split_members = [info for info in split_infos if info["split_name"]]
    if len(split_infos) <= 1 or not split_members:
        return None

    base_info = next((info for info in split_infos if not info["split_name"]), split_infos[0])
    base_path = base_info["path"]
    split_paths = [info["path"] for info in split_infos if info["path"] != base_path]
    if not split_paths:
        return None

    _ensure_tools()
    errors = []
    for apktool_jar in _apktool_candidates():
        try:
            return _merge_with_apktool(apktool_jar, base_path, split_paths, package_name, output_dir)
        except Exception as err:
            errors.append("{}: {}".format(os.path.basename(apktool_jar), err))

    raise ApkMergeError(" / ".join(errors))


def _ensure_tools():
    required = [
        APKTOOL_JAR,
        APKSIGNER_JAR,
        ZIPALIGN_EXE,
        SIGNING_KEY,
        SIGNING_CERT,
    ]
    missing = [path for path in required if not os.path.isfile(path)]
    if missing:
        raise ApkMergeError("Required merge tools are missing: {}".format(", ".join(missing)))


def _read_apk_info(apk_path):
    try:
        apk = APK(apk_path)
        manifest = apk.get_android_manifest_xml()
    except Exception as err:
        raise ApkMergeError("Failed to inspect {}: {}".format(apk_path, err))

    if manifest is None:
        raise ApkMergeError("AndroidManifest.xml not found in {}.".format(apk_path))

    root = manifest.getroot() if hasattr(manifest, "getroot") else manifest
    return {
        "path": apk_path,
        "package": apk.get_package(),
        "split_name": root.attrib.get("split"),
        "config_for_split": root.attrib.get("configForSplit"),
    }


def _apktool_candidates():
    candidates = []
    for candidate in (APKTOOL_JAR, APKTOOL_FALLBACK_JAR):
        if not os.path.isfile(candidate):
            continue
        if candidate in candidates:
            continue
        candidates.append(candidate)
    return candidates


def _merge_with_apktool(apktool_jar, base_path, split_paths, package_name, output_dir):
    temp_dir = _make_temp_dir()
    try:
        frame_dir = os.path.join(temp_dir, "apktool-frame")
        os.makedirs(frame_dir, exist_ok=True)

        merged_dir = os.path.join(temp_dir, "merged")
        decoded_base_dir = os.path.join(temp_dir, "decoded_base")
        _decode_apk(apktool_jar, frame_dir, base_path, decoded_base_dir)
        shutil.copytree(decoded_base_dir, merged_dir)

        for split_path in split_paths:
            decoded_split_dir = os.path.join(
                temp_dir,
                "decoded_{}".format(os.path.splitext(os.path.basename(split_path))[0]),
            )
            _decode_apk(apktool_jar, frame_dir, split_path, decoded_split_dir)
            _merge_manifest_file(
                os.path.join(merged_dir, "AndroidManifest.xml"),
                os.path.join(decoded_split_dir, "AndroidManifest.xml"),
            )
            _merge_decoded_tree(merged_dir, decoded_split_dir)

        _sanitize_merged_package(merged_dir)

        unsigned_apk = os.path.join(temp_dir, "merged-unsigned.apk")
        aligned_apk = os.path.join(temp_dir, "merged-aligned.apk")
        signed_apk = _build_output_path(output_dir, package_name)

        _run_command(
            ["java", "-jar", apktool_jar, "b", "-f", "-p", frame_dir, merged_dir, "-o", unsigned_apk],
            "Failed to rebuild merged APK with {}.".format(os.path.basename(apktool_jar)),
        )
        _run_command(
            [ZIPALIGN_EXE, "-f", "-p", "4", unsigned_apk, aligned_apk],
            "Failed to zipalign merged APK.",
        )
        _run_command(
            [
                "java",
                "-jar",
                APKSIGNER_JAR,
                "sign",
                "--key",
                SIGNING_KEY,
                "--cert",
                SIGNING_CERT,
                "--out",
                signed_apk,
                aligned_apk,
            ],
            "Failed to sign merged APK.",
        )
        _run_command(
            ["java", "-jar", APKSIGNER_JAR, "verify", "--verbose", signed_apk],
            "Merged APK verification failed.",
        )
        idsig_path = "{}.idsig".format(signed_apk)
        if os.path.isfile(idsig_path):
            os.remove(idsig_path)
        return signed_apk
    finally:
        _cleanup_temp_dir(temp_dir)


def _make_temp_dir():
    candidates = [
        os.path.join(os.getcwd(), ".tmp"),
        os.path.join(appdirs.user_cache_dir("fah"), "apkmerge"),
    ]
    errors = []
    for candidate in candidates:
        try:
            os.makedirs(candidate, exist_ok=True)
            temp_dir = os.path.join(candidate, "fah_merge_{}".format(uuid.uuid4().hex))
            os.makedirs(temp_dir, exist_ok=False)
            return temp_dir
        except OSError as err:
            errors.append("{}: {}".format(candidate, err))

    raise ApkMergeError("Unable to create a writable temp directory. {}".format(" / ".join(errors)))


def _cleanup_temp_dir(temp_dir):
    shutil.rmtree(temp_dir, ignore_errors=True)

    parent_dir = os.path.dirname(temp_dir)
    if not parent_dir:
        return

    try:
        if os.path.isdir(parent_dir) and not os.listdir(parent_dir):
            os.rmdir(parent_dir)
    except OSError:
        pass


def _decode_apk(apktool_jar, frame_dir, apk_path, output_dir):
    _run_command(
        ["java", "-jar", apktool_jar, "d", "-s", "-f", "-p", frame_dir, "-o", output_dir, apk_path],
        "Failed to decode {} with {}.".format(os.path.basename(apk_path), os.path.basename(apktool_jar)),
    )
    _prepare_decoded_dir(output_dir)


def _prepare_decoded_dir(decoded_dir):
    for dirname in ("build", "dist", "original"):
        shutil.rmtree(os.path.join(decoded_dir, dirname), ignore_errors=True)

    for maybe_meta_inf in (
        os.path.join(decoded_dir, "unknown", "META-INF"),
        os.path.join(decoded_dir, "META-INF"),
    ):
        _remove_signature_meta_files(maybe_meta_inf)


def _remove_signature_meta_files(meta_inf_dir):
    if not os.path.isdir(meta_inf_dir):
        return

    for root, _, filenames in os.walk(meta_inf_dir):
        for filename in filenames:
            if not _is_signature_meta_file(filename):
                continue
            try:
                os.remove(os.path.join(root, filename))
            except OSError:
                pass

    for root, dirnames, filenames in os.walk(meta_inf_dir, topdown=False):
        if dirnames or filenames:
            continue
        try:
            os.rmdir(root)
        except OSError:
            pass


def _is_signature_meta_file(filename):
    upper_name = filename.upper()
    return upper_name in SIGNATURE_META_FILENAMES or upper_name.endswith(SIGNATURE_META_SUFFIXES)


def _merge_decoded_tree(target_dir, source_dir):
    for entry in sorted(os.listdir(source_dir)):
        if entry in SKIP_TOP_LEVEL:
            continue

        source_path = os.path.join(source_dir, entry)
        if entry.startswith("classes") and entry.endswith(".dex") and os.path.isfile(source_path):
            target_dex_path = os.path.join(target_dir, _next_dex_name(target_dir, entry))
            shutil.copy2(source_path, target_dex_path)
            continue

        if entry == "res" and os.path.isdir(source_path):
            _merge_res_tree(os.path.join(target_dir, "res"), source_path)
            continue

        if entry.startswith("smali") and os.path.isdir(source_path):
            next_smali_dir = os.path.join(target_dir, _next_smali_dir_name(target_dir))
            shutil.copytree(source_path, next_smali_dir)
            continue

        _merge_tree(source_path, os.path.join(target_dir, entry))


def _merge_tree(source_path, target_path):
    if os.path.isdir(source_path):
        if not os.path.exists(target_path):
            shutil.copytree(source_path, target_path)
            return

        for entry in sorted(os.listdir(source_path)):
            _merge_tree(
                os.path.join(source_path, entry),
                os.path.join(target_path, entry),
            )
        return

    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    shutil.copy2(source_path, target_path)


def _merge_res_tree(target_res_dir, source_res_dir):
    if not os.path.isdir(target_res_dir):
        shutil.copytree(source_res_dir, target_res_dir)
        return

    for res_group in sorted(os.listdir(source_res_dir)):
        source_group_dir = os.path.join(source_res_dir, res_group)
        target_group_dir = os.path.join(target_res_dir, res_group)

        if not os.path.isdir(source_group_dir):
            _merge_tree(source_group_dir, target_group_dir)
            continue

        if not os.path.exists(target_group_dir):
            shutil.copytree(source_group_dir, target_group_dir)
            continue

        if res_group.startswith("values"):
            for entry in sorted(os.listdir(source_group_dir)):
                source_file = os.path.join(source_group_dir, entry)
                target_file = os.path.join(target_group_dir, entry)
                if not os.path.exists(target_file):
                    shutil.copy2(source_file, target_file)
                    continue
                _merge_values_xml(target_file, source_file)
            continue

        _merge_tree(source_group_dir, target_group_dir)


def _merge_values_xml(target_file, source_file):
    try:
        target_tree = ET.parse(target_file)
        source_tree = ET.parse(source_file)
    except ET.ParseError:
        shutil.copy2(source_file, target_file)
        return

    target_root = target_tree.getroot()
    source_root = source_tree.getroot()
    if _strip_xml_namespace(target_root.tag) != "resources" or _strip_xml_namespace(source_root.tag) != "resources":
        shutil.copy2(source_file, target_file)
        return

    existing_keys = {}
    for child in target_root:
        existing_keys[_resource_key(child)] = child

    changed = False
    for child in source_root:
        key = _resource_key(child)
        existing = existing_keys.get(key)
        if existing is None:
            target_root.append(copy.deepcopy(child))
            existing_keys[key] = child
            changed = True
            continue

        if ET.tostring(existing, encoding="unicode") == ET.tostring(child, encoding="unicode"):
            continue

    if changed:
        _write_xml(target_tree, target_file)


def _merge_manifest_file(target_manifest_path, source_manifest_path):
    target_tree = ET.parse(target_manifest_path)
    source_tree = ET.parse(source_manifest_path)
    target_root = target_tree.getroot()
    source_root = source_tree.getroot()

    target_app = _find_child(target_root, "application")
    source_app = _find_child(source_root, "application")
    if target_app is None and source_app is not None:
        target_app = copy.deepcopy(source_app)
        target_root.append(target_app)
    elif target_app is not None and source_app is not None:
        for attr_name, attr_value in source_app.attrib.items():
            if attr_name not in target_app.attrib:
                target_app.attrib[attr_name] = attr_value
        _merge_xml_children(target_app, source_app, _manifest_key)

    for child in source_root:
        tag = _strip_xml_namespace(child.tag)
        if tag in ("application",):
            continue
        if tag == "queries":
            _merge_manifest_queries(target_root, child)
            continue

        child_key = _manifest_key(child)
        if _find_existing_child(target_root, child_key, _manifest_key) is not None:
            continue
        target_root.append(copy.deepcopy(child))

    _write_xml(target_tree, target_manifest_path)


def _sanitize_merged_package(merged_dir):
    manifest_path = os.path.join(merged_dir, "AndroidManifest.xml")
    if not os.path.isfile(manifest_path):
        return

    tree = ET.parse(manifest_path)
    root = tree.getroot()
    for attr_name in SPLIT_MANIFEST_ATTRS:
        root.attrib.pop(attr_name, None)

    application = _find_child(root, "application")
    if application is not None:
        _remove_split_metadata(application)
        _normalize_has_code(application, merged_dir)

    _write_xml(tree, manifest_path)
    _remove_split_resources(merged_dir)
    _ensure_native_libs_uncompressed(merged_dir, application)


def _remove_split_metadata(application):
    for child in list(application):
        if _strip_xml_namespace(child.tag) != "meta-data":
            continue
        meta_name = child.attrib.get("{}name".format(ANDROID_NS), child.attrib.get("name"))
        if meta_name in REMOVABLE_METADATA_NAMES or _is_invalid_metadata(child):
            application.remove(child)


def _is_invalid_metadata(element):
    value = element.attrib.get("{}value".format(ANDROID_NS), element.attrib.get("value"))
    resource = element.attrib.get("{}resource".format(ANDROID_NS), element.attrib.get("resource"))

    if value == "@null" or resource == "@null":
        return True
    if value is None and resource is None:
        return True
    return False


def _remove_split_resources(merged_dir):
    res_xml_dir = os.path.join(merged_dir, "res", "xml")
    if not os.path.isdir(res_xml_dir):
        _remove_split_public_entries(merged_dir)
        return

    for entry in os.listdir(res_xml_dir):
        if entry.startswith("splits") and entry.endswith(".xml"):
            try:
                os.remove(os.path.join(res_xml_dir, entry))
            except OSError:
                pass

    _remove_split_public_entries(merged_dir)


def _remove_split_public_entries(merged_dir):
    public_xml_path = os.path.join(merged_dir, "res", "values", "public.xml")
    if not os.path.isfile(public_xml_path):
        return

    try:
        tree = ET.parse(public_xml_path)
    except ET.ParseError:
        return

    root = tree.getroot()
    changed = False
    for child in list(root):
        if _strip_xml_namespace(child.tag) != "public":
            continue
        if child.attrib.get("type") != "xml":
            continue
        name = child.attrib.get("name", "")
        if not name.startswith("splits"):
            continue
        root.remove(child)
        changed = True

    if changed:
        _write_xml(tree, public_xml_path)


def _merged_package_has_code(merged_dir):
    for entry in os.listdir(merged_dir):
        if entry.startswith("classes") and entry.endswith(".dex"):
            return True
        if entry.startswith("smali") and os.path.isdir(os.path.join(merged_dir, entry)):
            return True
    return False


def _normalize_has_code(application, merged_dir):
    attr_name = "{}hasCode".format(ANDROID_NS)
    current_value = application.attrib.get(attr_name)
    if current_value != "false":
        return

    if _merged_package_has_code(merged_dir):
        application.attrib[attr_name] = "true"


def _ensure_native_libs_uncompressed(merged_dir, application):
    if application is None:
        return

    extract_native_libs = application.attrib.get("{}extractNativeLibs".format(ANDROID_NS))
    if extract_native_libs != "false":
        return

    apktool_yml_path = os.path.join(merged_dir, "apktool.yml")
    if not os.path.isfile(apktool_yml_path):
        return

    with open(apktool_yml_path, "r", encoding="utf-8") as fp:
        lines = fp.readlines()

    if any(line.strip() == "- so" for line in lines):
        return

    updated_lines = []
    inserted = False
    for line in lines:
        updated_lines.append(line)
        if not inserted and line.strip() == "doNotCompress:":
            updated_lines.append("- so\n")
            inserted = True

    if not inserted:
        if updated_lines and not updated_lines[-1].endswith("\n"):
            updated_lines[-1] = updated_lines[-1] + "\n"
        updated_lines.extend(["doNotCompress:\n", "- so\n"])

    with open(apktool_yml_path, "w", encoding="utf-8", newline="\n") as fp:
        fp.writelines(updated_lines)


def _merge_manifest_queries(target_root, source_queries):
    target_queries = _find_child(target_root, "queries")
    if target_queries is None:
        target_root.append(copy.deepcopy(source_queries))
        return

    _merge_xml_children(target_queries, source_queries, _manifest_key)


def _merge_xml_children(target_parent, source_parent, key_builder):
    for child in source_parent:
        child_key = key_builder(child)
        if _find_existing_child(target_parent, child_key, key_builder) is not None:
            continue
        target_parent.append(copy.deepcopy(child))


def _find_existing_child(parent, child_key, key_builder):
    for child in parent:
        if key_builder(child) == child_key:
            return child
    return None


def _find_child(parent, tag_name):
    for child in parent:
        if _strip_xml_namespace(child.tag) == tag_name:
            return child
    return None


def _manifest_key(element):
    tag = _strip_xml_namespace(element.tag)
    name = element.attrib.get("{}name".format(ANDROID_NS), element.attrib.get("name"))
    authorities = element.attrib.get("{}authorities".format(ANDROID_NS))
    scheme = element.attrib.get("{}scheme".format(ANDROID_NS))
    host = element.attrib.get("{}host".format(ANDROID_NS))

    if tag == "queries":
        return ("queries",)
    if tag == "provider":
        return (tag, name, authorities)
    if tag == "data":
        return (tag, scheme, host)
    if name is not None:
        return (tag, name)
    return (tag, ET.tostring(element, encoding="unicode"))


def _resource_key(element):
    tag = _strip_xml_namespace(element.tag)
    name = element.attrib.get("name")
    item_type = element.attrib.get("type")
    resource_id = element.attrib.get("id")

    if tag == "public":
        return (tag, item_type, name, resource_id)
    if tag == "item":
        return (tag, item_type, name)
    if name is not None:
        return (tag, name)
    return (tag, ET.tostring(element, encoding="unicode"))


def _next_smali_dir_name(target_dir):
    max_index = 0
    for entry in os.listdir(target_dir):
        if entry == "smali":
            max_index = max(max_index, 1)
            continue
        if entry.startswith("smali_classes"):
            suffix = entry.replace("smali_classes", "", 1)
            if suffix.isdigit():
                max_index = max(max_index, int(suffix))

    next_index = max_index + 1
    if next_index == 1:
        return "smali"
    return "smali_classes{}".format(next_index)


def _next_dex_name(target_dir, source_name):
    if not os.path.exists(os.path.join(target_dir, source_name)):
        return source_name

    max_index = 1
    for entry in os.listdir(target_dir):
        if entry == "classes.dex":
            max_index = max(max_index, 1)
            continue
        if entry.startswith("classes") and entry.endswith(".dex"):
            suffix = entry[len("classes"):-len(".dex")]
            if suffix.isdigit():
                max_index = max(max_index, int(suffix))

    return "classes{}.dex".format(max_index + 1)


def _build_output_path(output_dir, package_name):
    base_name = "{}.apk".format(package_name)
    target_path = os.path.join(output_dir, base_name)
    if not os.path.exists(target_path):
        return target_path

    counter = 1
    while True:
        candidate = os.path.join(output_dir, "{}_{}.apk".format(package_name, counter))
        if not os.path.exists(candidate):
            return candidate
        counter += 1


def _run_command(command, error_prefix):
    process = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if process.returncode == 0:
        return process.stdout

    output = (process.stdout or "").strip()
    if output:
        raise ApkMergeError("{} {}".format(error_prefix, output))
    raise ApkMergeError(error_prefix)


def _strip_xml_namespace(tag):
    if not isinstance(tag, str):
        return None
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _write_xml(tree, target_path):
    if hasattr(ET, "indent"):
        ET.indent(tree, space="    ")
    xml_data = ET.tostring(tree.getroot(), encoding="unicode")
    with open(target_path, "w", encoding="utf-8", newline="\n") as fp:
        fp.write(XML_DECLARATION)
        fp.write(xml_data)
