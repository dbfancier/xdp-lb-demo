#!/bin/bash

sudo clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -I. -c xdp-lb.bpf.c -o xdp-proxy.bpf.o
sudo bpftool gen skeleton xdp-proxy.bpf.o > xdp-proxy.skel.h
sudo clang -g -O2 -Wall -I. -c main.c -o xdp-proxy.o
sudo clang -Wall -O2 -g xdp-proxy.o -static -lbpf -lelf -lz -o xdp-proxy
sudo docker restart lb
sudo docker cp xdp-proxy.bpf.o lb:/
sudo docker cp xdp-proxy lb:/
