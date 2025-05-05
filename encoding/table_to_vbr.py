import re
import sys

PATTERN = re.compile(r"\d+\s+\w+\s+([\dx]+)\s+\d+\s+\|[\s~]+[\d\w.]+\s+(\d+\w)")

table = {}

for line in sys.stdin:
    match = PATTERN.match(line)
    if match:
        table.setdefault(match.group(1), []).append(match.group(2))

ratio = 3840 / 2160


i = 0
previous = -1
for res, bitrates in table.items():
    # Skip all non-16:9
    w, h = res.split("x")
    if int(w) / int(h) != ratio:
        continue
    for bitrate in sorted(bitrates, key=lambda x: int(x[:-1])):
        # if previous >= int(bitrate[:-1]):
        #     continue
        previous = int(bitrate[:-1])
        print(f"""    -map 0:v -b:v:{i} {bitrate} -s:v:{i} {res} \\""")
        i += 1