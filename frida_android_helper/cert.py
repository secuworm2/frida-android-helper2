from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509
from datetime import datetime, timedelta
from uuid import uuid4
from importlib import resources
from frida_android_helper.utils import *
import shutil
import appdirs
import os
import subprocess
import tempfile

PATH_CACHE_CA_DER = os.path.join(appdirs.user_data_dir("fah"), "fah_ca.der")
PATH_CACHE_SERVER_KEY_DER = os.path.join(appdirs.user_data_dir("fah"), "fah_server_private_key.der")


def _log_section(title):
    eprint("")
    eprint("== {} ==".format(title))


def _log_line(message):
    eprint("- {}".format(message))


def _log_error(message):
    eprint("ERROR: {}".format(message))


def _log_next_steps(title, steps):
    eprint("NEXT: {}".format(title))
    for i, step in enumerate(steps, start=1):
        eprint("  {}. {}".format(i, step))


def _path_exists(device, path, root=False):
    out = perform_cmd(device, "[ -e {} ] && echo 1 || echo 0".format(path), root=root)
    return out.strip().endswith("1")


def _next_cert_offset(device, path_cacerts, x509_old_hash):
    offset = 0
    while _path_exists(device, "{}/{}.{}".format(path_cacerts, x509_old_hash, offset), root=True):
        offset += 1
    return offset


def _remount_system_rw(device):
    remount_cmds = [
        "mount -o rw,remount /system",
        "mount -o remount,rw /system",
        "mount -o rw,remount /",
        "mount -o remount,rw /",
        "mount -o rw,remount /system_root",
        "mount -o remount,rw /system_root",
    ]
    errors = []
    for cmd in remount_cmds:
        err = perform_cmd(device, cmd, root=True).strip()
        if not err:
            return ""
        errors.append("{} => {}".format(cmd, err.replace("\n", " ")))
    return "\n".join(errors)


def setup_certificate(_=None):
    _log_section("CERT SETUP RESULT")

    generate_result = generate_certificate(show_section=False)
    burp_result = export_burp_certificate(show_section=False, show_guidance=False)
    install_result = install_certificate(show_section=False, show_guidance=False)

    guide_steps = []
    if burp_result and burp_result.get("guide_steps"):
        guide_steps.extend(burp_result["guide_steps"])
    if install_result and install_result.get("next_steps"):
        guide_steps.extend(install_result["next_steps"])

    _log_section("WHAT YOU NEED TO DO")
    if guide_steps:
        for i, step in enumerate(guide_steps, start=1):
            eprint("{}. {}".format(i, step))
    else:
        _log_line("No additional action required.")

    if (not generate_result or not generate_result.get("ok", False)) or \
            (not burp_result or not burp_result.get("ok", False)) or \
            (not install_result or not install_result.get("ok", False)):
        _log_line("If there are errors above, resolve them and run `fah cert setup` again.")


def generate_certificate(_=None, show_section=True):
    if show_section:
        _log_section("GENERATE CERTIFICATE")

    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()
    builder = x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "DZ"),
        x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, "ORAN"),
        x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, "ORAN"),
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "FAH Corp"),
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME, "FAH"),
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "FAH CA"),
        x509.NameAttribute(x509.oid.NameOID.EMAIL_ADDRESS, "info@example.com"),
    ])).issuer_name(x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "DZ"),
        x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, "ORAN"),
        x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, "ORAN"),
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "FAH Corp"),
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME, "FAH"),
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "FAH CA"),
        x509.NameAttribute(x509.oid.NameOID.EMAIL_ADDRESS, "info@example.com"),
    ])).not_valid_before(datetime.today() - timedelta(days=1)) \
        .not_valid_after(datetime.today() + timedelta(days=365 * 2)) \
        .serial_number(int(uuid4())) \
        .public_key(public_key) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)

    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    with open("fah_server_private_key.der", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("fah_ca.der", "wb") as f:
        f.write(certificate.public_bytes(
            encoding=serialization.Encoding.DER
        ))

    os.makedirs(os.path.dirname(PATH_CACHE_CA_DER), exist_ok=True)
    shutil.copyfile("fah_ca.der", PATH_CACHE_CA_DER)
    shutil.copyfile("fah_server_private_key.der", PATH_CACHE_SERVER_KEY_DER)
    _log_line("Certificate generated: fah_ca.der, fah_server_private_key.der")
    return {
        "ok": True,
        "cert_file": "fah_ca.der",
        "key_file": "fah_server_private_key.der",
    }


def export_burp_certificate(password=None, show_section=True, show_guidance=True):
    if show_section:
        _log_section("EXPORT BURP BUNDLE")
    if password is None or not str(password).strip():
        password = "fah"

    cert_path = "fah_ca.der" if os.path.isfile("fah_ca.der") else PATH_CACHE_CA_DER
    key_path = "fah_server_private_key.der" if os.path.isfile("fah_server_private_key.der") else PATH_CACHE_SERVER_KEY_DER

    if not os.path.isfile(cert_path):
        _log_error("Certificate not found. Run `fah cert generate` or `fah cert setup` first.")
        return {"ok": False, "guide_steps": []}
    if not os.path.isfile(key_path):
        _log_error("Private key not found. Run `fah cert generate` or `fah cert setup` first.")
        return {"ok": False, "guide_steps": []}

    with open(cert_path, "rb") as f:
        cert_data = f.read()
    with open(key_path, "rb") as f:
        key_data = f.read()

    cert = x509.load_der_x509_certificate(cert_data, default_backend())
    key = serialization.load_der_private_key(key_data, password=None, backend=default_backend())
    if key is None:
        _log_error("Failed to load private key from {}.".format(key_path))
        return {"ok": False, "guide_steps": []}

    p12_bytes = pkcs12.serialize_key_and_certificates(
        name=b"FAH CA",
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
    )

    out_file = "fah_ca_for_burp.p12"
    with open(out_file, "wb") as f:
        f.write(p12_bytes)

    _log_line("Burp bundle created: {}".format(out_file))
    guide_steps = [
        "In Burp: Proxy tab -> Proxy settings",
        "Proxy listeners -> Import / export CA certificate",
        "Import -> PKCS#12 -> select {}".format(out_file),
        "Enter password: {}".format(password),
    ]
    if show_guidance:
        _log_next_steps("Import certificate into Burp", guide_steps)
    return {
        "ok": True,
        "bundle_file": out_file,
        "password": password,
        "guide_steps": guide_steps,
    }


def install_certificate(certificate=None, show_section=True, show_guidance=True):
    if show_section:
        _log_section("INSTALL CERTIFICATE")
    errors = []

    def _emit_error(message):
        errors.append(message)
        _log_error(message)

    # hardcoded one from running
    # openssl x509 -inform DER -subject_hash_old -in fah_ca.der
    x509_old_hash = "35aa2e12"
    if certificate is None:
        if os.path.isfile("fah_ca.der"):
            certificate = "fah_ca.der"
        elif os.path.isfile("cacert.der"):  # burp'ish
            certificate = "cacert.der"
        elif os.path.isfile(PATH_CACHE_CA_DER):  # we got a cert in the cache!
            certificate = PATH_CACHE_CA_DER
        else:
            _emit_error("fah_ca.der / cacert.der not found.")
            return {"ok": False, "next_steps": [], "errors": errors}

        if os.path.isfile("fah_ca.der") or os.path.isfile("cacert.der"):  # in case we did not get it from cache
            os.makedirs(os.path.dirname(PATH_CACHE_CA_DER), exist_ok=True)
            shutil.copyfile(certificate, PATH_CACHE_CA_DER)
    else:
        if os.path.isfile(certificate):
            # TODO: implement this using pure python cryptography module.
            # https://github.com/openssl/openssl/blob/47b4ccea9cb9b924d058fd5a8583f073b7a41656/crypto/x509/x509_cmp.c#L207
            result = subprocess.run(
                ["openssl", "x509", "-inform", "DER", "-subject_hash_old", "-in", certificate, "-noout"],
                capture_output=True)
            if result.returncode == 0:
                x509_old_hash = result.stdout.strip().decode("utf-8")
                os.makedirs(os.path.dirname(PATH_CACHE_CA_DER), exist_ok=True)
                shutil.copyfile(certificate, PATH_CACHE_CA_DER)
            else:
                _emit_error(result.stderr.decode("utf-8"))
                return {"ok": False, "next_steps": [], "errors": errors}
        else:
            _emit_error("{} not found.".format(certificate))
            return {"ok": False, "next_steps": [], "errors": errors}

    # install certificates on devices
    devices = get_adb_devices()
    if not devices:
        _emit_error("No connected devices. Certificate was generated/exported only.")
        return {"ok": False, "next_steps": [], "errors": errors}

    installed_devices = []
    need_reboot = []
    soft_rebooted = []
    for device in devices:
        device_name = "{} ({})".format(get_device_model(device), device.get_serial_no())
        path_cacerts = "/system/etc/security/cacerts"

        device.push(certificate, "/data/local/tmp/{}".format(x509_old_hash))

        # Powered by https://www.g1a55er.net/Android-14-Still-Allows-Modification-of-System-Certificates
        if get_android_version(device) >= 14:
            path_cacerts = "/apex/com.android.conscrypt/cacerts"

            script_bytes = resources.files("frida_android_helper").joinpath("scripts", "android14_apex.sh").read_bytes()
            script_bytes = script_bytes.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
            with tempfile.NamedTemporaryFile(mode="wb", suffix=".sh", delete=False) as tmp:
                tmp.write(script_bytes)
                tmp_path = tmp.name
            try:
                device.push(tmp_path, "/data/local/tmp/android14_apex.sh")
            finally:
                os.unlink(tmp_path)

            err = perform_cmd(device, "sh /data/local/tmp/android14_apex.sh", root=True)
            if err:
                _emit_error("[{}] {}".format(device_name, err))
                continue
        else:
            remount_targets = [
                "/system/etc/security/cacerts",
                "/system/system/etc/security/cacerts",
                "/system_root/system/etc/security/cacerts",
            ]
            for target in remount_targets:
                if _path_exists(device, target, root=True):
                    path_cacerts = target
                    break

            err = _remount_system_rw(device)
            if err:
                _emit_error("[{}] {}".format(device_name, err))
                continue

        if not _path_exists(device, path_cacerts, root=True):
            _emit_error("[{}] Target cacerts path not found: {}".format(device_name, path_cacerts))
            continue

        offset = _next_cert_offset(device, path_cacerts, x509_old_hash)
        err = perform_cmd(device, "mv /data/local/tmp/{} {}/{}.{}".format(x509_old_hash, path_cacerts, x509_old_hash, offset), root=True)
        if err:
            _emit_error("[{}] {}".format(device_name, err))
            continue

        err = perform_cmd(device, "chown root:root {}/{}.{}".format(path_cacerts, x509_old_hash, offset), root=True)
        if err:
            _emit_error("[{}] {}".format(device_name, err))
            continue
        err = perform_cmd(device, "chmod 644 {}/{}.{}".format(path_cacerts, x509_old_hash, offset), root=True)
        if err:
            _emit_error("[{}] {}".format(device_name, err))
            continue

        if get_android_version(device) >= 14:
            perform_cmd(device, "chcon u:object_r:system_file:s0 {}/{}.{}".format(path_cacerts, x509_old_hash, offset), root=True)

        installed_devices.append(device_name)
        if get_android_version(device) >= 14:
            perform_cmd(device, "killall system_server", root=True)
            soft_rebooted.append(device_name)
        else:
            need_reboot.append(device_name)

    if not installed_devices:
        _emit_error("Failed to install certificate on all connected devices.")
        return {"ok": False, "next_steps": [], "errors": errors}

    _log_line("Installed certificate on {} device(s).".format(len(installed_devices)))
    for device_name in installed_devices:
        eprint("  - {}".format(device_name))

    next_steps = []
    if need_reboot:
        next_steps.append("Reboot these device(s): {}".format(", ".join(need_reboot)))
    if soft_rebooted:
        next_steps.append("Android 14+ device(s) already soft-rebooted: {}".format(", ".join(soft_rebooted)))
        next_steps.append("Do not manually reboot Android 14+ devices unless necessary.")
    if show_guidance and next_steps:
        _log_next_steps("What you need to do", next_steps)
    return {
        "ok": True,
        "installed_devices": installed_devices,
        "need_reboot": need_reboot,
        "soft_rebooted": soft_rebooted,
        "next_steps": next_steps,
        "errors": errors,
    }
