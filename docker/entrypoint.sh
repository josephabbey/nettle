#!/bin/sh
set -eu

config_path="${NETTLE_CONFIG:-/etc/nettle/Nettlefile}"

exec /usr/local/bin/nettle -config "$config_path" "$@"
