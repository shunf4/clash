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

# Uses -d "@ts" (GNU) then -r ts
# (busybox/BSD) then bare date as portable fallback.
make_ts() {
    local ts
	local fmt_utc
	local fmt_local
	ts="$(date +%s)"
	fmt_utc="+%Y-%m-%d_%H:%M:%S_UTC"
	fmt_local="+%Y-%m-%d_%H:%M:%S_%Z"
    { TZ=UTC date -d "@$ts" "$fmt_utc" 2>/dev/null || TZ=UTC date -r "$ts" "$fmt_utc" 2>/dev/null || date -u "$fmt_utc"; } | tr -d '\r\n'
	echo -n '___'
    { date -d "@$ts" "$fmt_local" 2>/dev/null || date -r "$ts" "$fmt_local" 2>/dev/null || date "$fmt_local"; } | tr -d '\r\n'
}

for os in windows linux darwin ; do
	suffix=""
	if [ "$os" = "darwin" ]; then suffix=".rivet.macos"; fi
	if [ "$os" = "linux" ]; then suffix=".rivet.linuxx64"; fi
	if [ "$os" = "windows" ]; then suffix=".rivet.windows.exe"; fi

	v="$(git rev-parse --short HEAD)-upstream_alpha_$(git merge-base HEAD upstream/Alpha | cut -c1-8)-upstream_meta_$(git merge-base HEAD upstream/Meta | cut -c1-8)"
	tsf="$(make_ts)"

	( set -x

	GOOS=$os go build -tags with_gvisor -trimpath -ldflags "-X \"github.com/metacubex/mihomo/constant.Version=${v}\" \
		-X \"github.com/metacubex/mihomo/constant.BuildTime=${tsf}\" \
		-w -s -buildid=" -v -o ./bin/mhm"$suffix"
	
	)
done

GOOS=linux GOARCH=arm64 go build -v -o ./bin/mhm.rivet.linuxarm64
