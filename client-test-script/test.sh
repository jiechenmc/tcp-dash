#!/usr/bin/env bash

echo "Loading modules..."
sudo modprobe tcp_bbr
sudo modprobe tcp_westwood
sudo modprobe tcp_htcp
sudo modprobe tcp_cubic

echo "Testing with CUBIC..."
sudo sysctl -w net.ipv4.tcp_congestion_control=cubic
sleep 3
node main.js "$@"
sleep 3

echo "Testing with BBR..."
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr
sleep 3
node main.js "$@"
sleep 3

echo "Testing with Westwood..."
sudo sysctl -w net.ipv4.tcp_congestion_control=westwood
sleep 3
node main.js "$@"
sleep 3

echo "Testing with HTCP..."
sudo sysctl -w net.ipv4.tcp_congestion_control=htcp
sleep 3
node main.js "$@"
sleep 3

