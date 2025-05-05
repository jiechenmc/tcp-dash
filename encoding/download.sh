#!/usr/bin/env bash

set -e

mkdir raw || true
pushd raw
yt-dlp --embed-metadata --embed-subs --sub-langs all,-live_chat "$1"
popd
