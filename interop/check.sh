#!/bin/sh
# Writes sample archives with zipcrypt and checks that other tools open them:
# Info-ZIP unzip and Python's zipfile (ZipCrypto only), libarchive's bsdtar and
# 7-Zip (both methods). Tools that are not installed are skipped, unless
# STRICT=1 is set, as it is in CI.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
pw=pw1234

# The samples have Korean file names; extracting them needs a UTF-8 locale.
case $(uname) in
Darwin) export LC_ALL=en_US.UTF-8 ;;
*) export LC_ALL=C.UTF-8 ;;
esac

(cd "$here" && ZIPCRYPT_SAMPLES="$dir" go test -count=1 -run '^TestWriteSamples$' .)
cd "$dir"
failed=0

have() {
	if command -v "$1" >/dev/null 2>&1; then
		return 0
	fi
	if [ "${STRICT:-}" = 1 ]; then
		echo "FAIL $1 is not installed"
		failed=1
	else
		echo "skip $1 is not installed"
	fi
	return 1
}

# same reports whether every source file was extracted to $1 unchanged.
same() {
	for f in src/*; do
		cmp -s "$f" "$1/$(basename "$f")" || return 1
	done
}

result() { # tool archive status
	if [ "$3" = 0 ]; then
		echo "ok   $1 $2"
	else
		echo "FAIL $1 $2"
		failed=1
	fi
}

if have unzip; then
	for z in zc-*.zip; do
		rm -rf out && mkdir out
		s=0
		unzip -q -P "$pw" -d out "$z" && same out || s=1
		result unzip "$z" $s
	done
fi

if have python3; then
	for z in zc-*.zip; do
		s=0
		python3 - "$z" "$pw" <<'EOF' || s=1
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    for info in z.infolist():
        with open("src/" + info.filename, "rb") as f:
            assert z.read(info, pwd=sys.argv[2].encode()) == f.read(), info.filename
EOF
		result python3 "$z" $s
	done
fi

if have bsdtar; then
	for z in *.zip; do
		rm -rf out && mkdir out
		s=0
		bsdtar -x -f "$z" -C out --passphrase "$pw" && same out || s=1
		result bsdtar "$z" $s
	done
fi

sevenzip=""
for c in 7zz 7z; do
	if command -v $c >/dev/null 2>&1; then
		sevenzip=$c
		break
	fi
done
if [ -n "$sevenzip" ] || have 7z; then
	for z in *.zip; do
		rm -rf out
		s=0
		$sevenzip x -y -bd -p"$pw" -oout "$z" >/dev/null && same out || s=1
		result "$sevenzip" "$z" $s
	done
fi

exit $failed
