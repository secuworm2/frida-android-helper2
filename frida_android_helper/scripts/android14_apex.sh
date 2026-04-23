#!/bin/sh
# Mount a tmpfs over the APEX cacerts directory so system CA certs can be added at runtime.
# Works on Android 14+ without needing to unmount the APEX or disable SELinux globally.
APEX_CERTS="/apex/com.android.conscrypt/cacerts"
STAGING="/data/local/tmp/ca-staging-$$"

mkdir -p "$STAGING"
cp "$APEX_CERTS/"* "$STAGING/" 2>/dev/null

if ! grep -q "tmpfs $APEX_CERTS" /proc/mounts; then
    mount -t tmpfs tmpfs "$APEX_CERTS"
fi

cp "$STAGING/"* "$APEX_CERTS/"
chown root:root "$APEX_CERTS/"*
chmod 644 "$APEX_CERTS/"*
chcon u:object_r:system_file:s0 "$APEX_CERTS/"* 2>/dev/null

rm -rf "$STAGING"
