#!/usr/bin/env bash
# Attach a physical USB port to a libvirt system VM and retain the attachment.
#
# Defaults are deliberately suitable for the Tendyron token on USB port 1-3:
#   sudo scripts/attach_usb_port_to_vm.sh
#
# Override them without editing the script:
#   VM_NAME=myvm USB_PORT=2-1 sudo scripts/attach_usb_port_to_vm.sh
set -euo pipefail

VM_NAME="${VM_NAME:-win8.1}"
USB_PORT="${USB_PORT:-1-3}"
VIRSH=(virsh --connect qemu:///system)
USB_SYSFS="/sys/bus/usb/devices/${USB_PORT}"

if [[ ${EUID} -ne 0 ]]; then
    echo "Run with sudo so libvirt can access qemu:///system." >&2
    exit 2
fi

for field in idVendor idProduct busnum devnum; do
    if [[ ! -r "${USB_SYSFS}/${field}" ]]; then
        echo "USB port ${USB_PORT} is not present or is not a USB device (${USB_SYSFS}/${field})." >&2
        exit 1
    fi
done

vendor="$(<"${USB_SYSFS}/idVendor")"
product="$(<"${USB_SYSFS}/idProduct")"
bus="$(<"${USB_SYSFS}/busnum")"
device="$(<"${USB_SYSFS}/devnum")"

if ! "${VIRSH[@]}" dominfo "${VM_NAME}" >/dev/null 2>&1; then
    echo "No libvirt system VM named '${VM_NAME}'." >&2
    exit 1
fi

xml_file="$(mktemp)"
static_xml_file="$(mktemp)"
err_file="$(mktemp)"
trap 'rm -f "${xml_file}" "${static_xml_file}" "${err_file}"' EXIT
cat >"${xml_file}" <<EOF
<hostdev mode='subsystem' type='usb'>
  <source startupPolicy='optional'>
    <vendor id='0x${vendor}'/>
    <product id='0x${product}'/>
  </source>
</hostdev>
EOF
cat >"${static_xml_file}" <<EOF
<hostdev mode='subsystem' type='usb'>
  <source>
    <address bus='${bus}' device='${device}'/>
  </source>
</hostdev>
EOF

echo "USB ${USB_PORT}: ${vendor}:${product} (current bus ${bus}, device ${device})"

# If the old bus/device definition is attached to the active VM, remove it
# first.  This avoids trying to assign the same physical token twice while the
# persistent definition is upgraded to vendor/product matching.
state="$("${VIRSH[@]}" domstate "${VM_NAME}")"
if [[ ${state} == running ]]; then
    if "${VIRSH[@]}" detach-device "${VM_NAME}" "${static_xml_file}" --live 2>"${err_file}"; then
        echo "Detached the active bus/device attachment before upgrading it."
    elif ! rg -q 'not found|No device|No matching' "${err_file}"; then
        cat "${err_file}" >&2
        exit 1
    fi
fi

# Replace a previously saved bus/device attachment for this presently connected
# device.  A vendor/product source remains valid after reconnecting the token.
if "${VIRSH[@]}" detach-device "${VM_NAME}" "${static_xml_file}" --config 2>"${err_file}"; then
    echo "Replaced the previous bus/device attachment with a stable USB identity."
elif ! rg -q 'not found|No device' "${err_file}"; then
    cat "${err_file}" >&2
    exit 1
fi

if "${VIRSH[@]}" attach-device "${VM_NAME}" "${xml_file}" --config 2>"${err_file}"; then
    echo "Persistent USB attachment added to ${VM_NAME}."
elif rg -q 'already in the domain configuration' "${err_file}"; then
    echo "Persistent USB attachment is already configured for ${VM_NAME}."
else
    cat "${err_file}" >&2
    exit 1
fi

if [[ ${state} == running ]]; then
    if "${VIRSH[@]}" dumpxml "${VM_NAME}" | rg -q "<vendor id='0x${vendor}'/>" \
        && "${VIRSH[@]}" dumpxml "${VM_NAME}" | rg -q "<product id='0x${product}'/>"; then
        echo "USB is already attached to the running VM."
    elif "${VIRSH[@]}" attach-device "${VM_NAME}" "${xml_file}" --live 2>"${err_file}"; then
        echo "USB attached to the running VM."
    elif rg -q 'already.*domain|exists' "${err_file}"; then
        echo "USB is already attached to the running VM."
    else
        cat "${err_file}" >&2
        exit 1
    fi
else
    echo "VM is ${state}; USB will be attached when it starts."
fi
