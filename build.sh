#!/bin/sh

for os in windows linux darwin ; do
	suffix=""
	if [ "$os" = "darwin" ]; then suffix=".rivet.macos"; fi
	if [ "$os" = "linux" ]; then suffix=".rivet.linux"; fi
	if [ "$os" = "windows" ]; then suffix=".rivet.windows.exe"; fi
	GOOS=$os go build -v -o ./bin/clash"$suffix"
done

GOOS=linux GOARCH=arm64 go build -v -o ./bin/linux-arm64/clash.rivet.linux
