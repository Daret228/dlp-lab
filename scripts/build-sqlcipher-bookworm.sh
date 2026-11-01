#!/bin/bash
# Build the runtime library from Debian's verified, patched 4.6.1-2 source.
# Source must be obtained with apt-get source against authenticated indexes.
set -euo pipefail
[[ $# == 1 ]] || { echo 'Usage: build-sqlcipher-bookworm.sh SOURCE_DIR' >&2; exit 2; }
source_dir=$(realpath "$1")
cd "$source_dir"
[[ $(dpkg-parsechangelog -S Version) == 4.6.1-2 ]] || { echo 'Expected Debian source 4.6.1-2' >&2; exit 2; }
export DEB_BUILD_MAINT_OPTIONS=hardening=+all
export CFLAGS="$(dpkg-buildflags --get CFLAGS) -fno-strict-aliasing -DSQLITE_SECURE_DELETE -DSQLITE_ENABLE_COLUMN_METADATA -DSQLITE_ENABLE_FTS3 -DSQLITE_ENABLE_RTREE=1 -DSQLITE_SOUNDEX=1 -DSQLITE_ENABLE_UNLOCK_NOTIFY -DSQLITE_OMIT_LOOKASIDE=1 -DSQLITE_ENABLE_UPDATE_DELETE_LIMIT=1 -DSQLITE_MAX_SCHEMA_RETRY=25 -DSQLITE_HAS_CODEC -DHAVE_USLEEP=1"
export CPPFLAGS="$(dpkg-buildflags --get CPPFLAGS)"
export LDFLAGS="$(dpkg-buildflags --get LDFLAGS)"
./configure --prefix=/usr --enable-threadsafe --enable-load-extension --enable-tempstore --enable-fts4 --enable-fts5 --enable-json --disable-tcl
make -j2
stage=$(mktemp -d "$source_dir/runtime-package.XXXXXX")
arch=$(dpkg-architecture -qDEB_HOST_ARCH)
multiarch=$(dpkg-architecture -qDEB_HOST_MULTIARCH)
mkdir -p "$stage/DEBIAN" "$stage/usr/lib/$multiarch" "$stage/usr/share/doc/libsqlcipher1"
cp -a .libs/libsqlcipher.so.1* "$stage/usr/lib/$multiarch/"
find "$stage/usr/lib/$multiarch" -type f -exec strip --strip-unneeded {} +
cp debian/copyright "$stage/usr/share/doc/libsqlcipher1/copyright"
deps=$(dpkg-shlibdeps -O .libs/libsqlcipher.so.1 | sed -n 's/^shlibs:Depends=//p')
[[ -n $deps ]]
cat > "$stage/DEBIAN/control" <<EOF
Package: libsqlcipher1
Version: 4.6.1-2~dlplab12.1
Architecture: $arch
Maintainer: DLP Lab contributors <noreply@invalid.example>
Depends: $deps
Section: libs
Priority: optional
Description: SQLCipher 4 runtime rebuilt for the DLP Lab Debian 12 test host
 Local rebuild of Debian source 4.6.1-2 against bookworm libraries.
EOF
printf '%s\n' 'libsqlcipher 1 libsqlcipher1 (>= 4.6.1)' > "$stage/DEBIAN/shlibs"
printf '%s\n' 'activate-noawait ldconfig' > "$stage/DEBIAN/triggers"
chmod -R go-w "$stage"
chmod 0755 "$stage"
dpkg-deb --root-owner-group --build "$stage" "../libsqlcipher1_4.6.1-2~dlplab12.1_${arch}.deb"
