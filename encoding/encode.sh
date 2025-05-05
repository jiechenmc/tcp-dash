#!/usr/bin/env bash

set -e

mkdir reencode || true

for i in "$@"
do
    filename="$(basename "$i")"
    filename_no_ext="${filename%.*}"
    ffmpeg -i "$i" -c:v h264_videotoolbox -c:a copy "reencode/$filename_no_ext.mp4"
done

