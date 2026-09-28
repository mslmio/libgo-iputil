#!/bin/bash

# Vendors github.com/mslmio/bogon-ip at a release into bogon-ip/, or checks that the copy there is
# byte for byte the release its VERSION names.
#
#   scripts/sync-bogon-ip.sh v1.1.0     # take that release
#   scripts/sync-bogon-ip.sh --check    # CI's check

set -euo pipefail

REPO=https://github.com/mslmio/bogon-ip.git
FILES=(ipv4.txt ipv6.txt vectors.tsv)

function main() {
    if [ "$#" -ne 1 ] ; then
        echo "usage: $0 v<major>.<minor>.<patch> | --check" >&2
        exit 2
    fi
    cd "$(dirname "$0")/.."
    # Global, so the EXIT trap can still read it once main has returned.
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT
    if [ "$1" = "--check" ] ; then
        check "$TMP" "$(cat bogon-ip/VERSION)"
    else
        take "$TMP" "$1"
    fi
}

function take() {
    local tmp="$1" tag="$2" f
    fetch "$tmp" "$tag"
    for f in "${FILES[@]}" ; do
        cp "$tmp/$f" "bogon-ip/$f"
    done
    echo "$tag" > bogon-ip/VERSION
    echo "bogon-ip/ is ${tag}"
}

function check() {
    local tmp="$1" tag="$2" f rc=0
    fetch "$tmp" "$tag"
    for f in "${FILES[@]}" ; do
        if ! cmp -s "$tmp/$f" "bogon-ip/$f" ; then
            echo "bogon-ip/$f is not ${tag}'s: run scripts/sync-bogon-ip.sh ${tag}" >&2
            rc=1
        fi
    done
    if [ "$rc" -eq 0 ] ; then
        echo "bogon-ip/ is ${tag}"
    fi
    return "$rc"
}

function fetch() {
    local tmp="$1" tag="$2"
    if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] ; then
        echo "${tag}: a release is v<major>.<minor>.<patch>" >&2
        exit 2
    fi
    git -c advice.detachedHead=false clone -q --depth 1 --branch "$tag" "$REPO" "$tmp"
}

main "$@"
