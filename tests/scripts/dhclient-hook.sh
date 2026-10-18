#!/bin/sh
# Только лабораторный veth: без штатного dhclient-script, DNS и маршрутов.
set -eu
[ "${interface:-}" = "cli0" ] || exit 1
[ -n "${LAB_NETNS:-}" ] || exit 1
[ "$(readlink /proc/self/ns/net)" = "$LAB_NETNS" ] || exit 1
[ -n "${LAB_EVENTS:-}" ] || exit 1
case "${reason:-}" in
    PREINIT) ip link set dev "$interface" up ;;
    BOUND|RENEW|REBIND|REBOOT)
        ip -4 address replace "$new_ip_address/24" dev "$interface"
        printf '%s %s\n' "$reason" "$new_ip_address" >> "$LAB_EVENTS"
        ;;
    EXPIRE|FAIL|RELEASE) ip -4 address flush dev "$interface" ;;
    # STOP сохраняет адрес; dhclient -x не отправляет DHCPRELEASE.
esac
exit 0
