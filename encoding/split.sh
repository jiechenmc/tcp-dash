#!/usr/bin/env bash

set -e 


mkdir split || true


for i in "$@"
do
    filename="$(basename "$i")"
    # Run the ffmpeg command and place output in the respective folder
    ffmpeg -y \
    -hwaccel videotoolbox \
    -i "$i" \
    -c:v h264_videotoolbox \
    -map 0:v -b:v:0 72k -s:v:0 256x144 \
    -map 0:v -b:v:1 76k -s:v:1 256x144 \
    -map 0:v -b:v:2 81k -s:v:2 256x144 \
    -map 0:v -b:v:3 84k -s:v:3 256x144 \
    -map 0:v -b:v:4 166k -s:v:4 256x144 \
    -map 0:v -b:v:5 169k -s:v:5 256x144 \
    -map 0:v -b:v:6 214k -s:v:6 640x360 \
    -map 0:v -b:v:7 320k -s:v:7 640x360 \
    -map 0:v -b:v:8 330k -s:v:8 640x360 \
    -map 0:v -b:v:9 635k -s:v:9 640x360 \
    -map 0:v -b:v:10 732k -s:v:10 640x360 \
    -map 0:v -b:v:11 674k -s:v:11 1280x720 \
    -map 0:v -b:v:12 980k -s:v:12 1280x720 \
    -map 0:v -b:v:13 1106k -s:v:13 1280x720 \
    -map 0:v -b:v:14 1499k -s:v:14 1280x720 \
    -map 0:v -b:v:15 2074k -s:v:15 1280x720 \
    -map 0:v -b:v:16 1226k -s:v:16 1920x1080 \
    -map 0:v -b:v:17 1767k -s:v:17 1920x1080 \
    -map 0:v -b:v:18 2781k -s:v:18 1920x1080 \
    -map 0:v -b:v:19 2974k -s:v:19 1920x1080 \
    -map 0:v -b:v:20 4692k -s:v:20 1920x1080 \
    -map 0:v -b:v:21 3486k -s:v:21 2560x1440 \
    -map 0:v -b:v:22 4676k -s:v:22 2560x1440 \
    -map 0:v -b:v:23 8631k -s:v:23 2560x1440 \
    -map 0:v -b:v:24 6978k -s:v:24 3840x2160 \
    -map 0:v -b:v:25 13308k -s:v:25 3840x2160 \
    -map 0:v -b:v:26 18625k -s:v:26 3840x2160 \
    -map 0:a:0 \
    -f dash -seg_duration 3 -use_template 1 -use_timeline 1 \
    -init_seg_name "${filename}_chunk_\$RepresentationID\$_init.m4s" \
    -media_seg_name "${filename}_chunk_\$RepresentationID\$_\$Bandwidth\$_\$Number\$.m4s" \
    -adaptation_sets "id=0,streams=v id=1,streams=a" \
    "split/${filename}_output.mpd"
done
