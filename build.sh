#!/bin/bash

[ -r /etc/profile.d/01-kto-startup.source.sh ] && source /etc/profile.d/01-kto-startup.source.sh

if [ "$IN_WINGCCENV" != "1" ] && [[ "$(type kto_wingccenv | head -n 1)" = *" is a function" ]]; then
	IN_WINGCCENV=1 kto_wingccenv bash "$0" "$@"
	exit "$?"
fi

if [ "$IN_FQ" != "1" ] && [[ "$(type fq | head -n 1)" = *" is a function" ]]; then
	IN_FQ=1 fq bash "$0" "$@"
	exit "$?"
fi

for os in windows linux darwin ; do
	suffix=""
	if [ "$os" = "darwin" ]; then suffix=".rivet.macos"; fi
	if [ "$os" = "linux" ]; then suffix=".rivet.linuxx64"; fi
	if [ "$os" = "windows" ]; then suffix=".rivet.windows.exe"; fi
	GOOS=$os go build -v -o ./bin/mhm"$suffix"
done

GOOS=linux GOARCH=arm64 go build -v -o ./bin/mhm.rivet.linuxarm64
