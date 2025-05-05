#!/usr/bin/env bash

WEBHOOK_URL=""
USER=""
SERVER="int.dhinak.net"

webhook() {
  if [[ ! -z "$2" && -f "$2" ]]; then
    curl -i \
      -F "payload_json={\"content\": \"$USER $1\"}" \
      -F "file1=@$2" \
      "$WEBHOOK_URL"
  else
    curl -i -H "Content-Type:application/json" \
      --data "{\"content\": \"$USER $1\"}" \
      "$WEBHOOK_URL"
  fi
}

abort() {
  echo "ERROR: $1!"
  webhook "ERROR: $1!"
  exit 1
}

rm -f out*.db out*.db.zip

echo "Loading modules..."
sudo modprobe tcp_bbr || abort "Load BBR"
sudo modprobe tcp_westwood || abort "Load Westwood"
sudo modprobe tcp_htcp || abort "Load HTCP"
sudo modprobe tcp_cubic || abort "Load CUBIC"

sshpass -p user ssh "$SERVER" "sudo tc qdisc add dev ens33 root netem rate 10mbit delay 20ms loss 0%" || echo 'Fail to add, possibly already set?'
sleep 1

for i in $(seq 1 3);
do
    if [[ "$i" -eq 1 ]]; then
        mode="low"
        delay=20
        loss=0
    elif [[ "$i" -eq 2 ]]; then
        mode="high"
        delay=100
        loss=1
    else
        mode="higher"
        delay=200
        loss=2
    fi

    echo "Setting $mode..."
    sshpass -p user ssh "$SERVER" "sudo tc qdisc change dev ens33 root netem rate 10mbit delay ${delay}ms loss ${loss}%" || abort "Set $mode"
    sleep 5

    echo "Testing with $mode CUBIC..."
    sudo sysctl -w net.ipv4.tcp_congestion_control=cubic || abort "Set CUBIC"
    sleep 3
    node main.js "CUBIC" "${mode^}" "$@"
    sleep 3

    echo "Testing with $mode BBR..."
    sudo sysctl -w net.ipv4.tcp_congestion_control=bbr || abort "Set BBR"
    sleep 3
    node main.js "BBR" "${mode^}" "$@"
    sleep 3

    echo "Testing with $mode Westwood..."
    sudo sysctl -w net.ipv4.tcp_congestion_control=westwood || abort "Set Westwood"
    sleep 3
    node main.js "Westwood" "${mode^}" "$@"
    sleep 3

    echo "Testing with $mode HTCP..."
    sudo sysctl -w net.ipv4.tcp_congestion_control=htcp || abort "Set HTCP"
    sleep 3
    node main.js "HTCP" "${mode^}" "$@"
    sleep 3

    mv "out.db" "out-${mode}.db"
    zip -qry "out-${mode}.db.zip" "out-${mode}.db"
    webhook "${mode} done" "out-${mode}.db.zip"

    sleep 30
done

webhook "Done"
