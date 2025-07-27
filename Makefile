build:
	@clang -I/usr/include/x86_64-linux-gnu -O2 -target bpf -c xdp-drop-kern.c -o bin/xdp-drop.o

load: build
	@sudo ip link set dev lo xdp obj bin/xdp-drop.o sec xdp

unload:
	@sudo ip link set lo xdpgeneric off

verify:
	@ip link show dev lo | grep prog/xdp

build_cli:
	@go build -o bin/main app/main.go
