#!/bin/bash

cd /source/thirdparty/libevent

rm -rf build
mkdir build
cd build

cmake \
  -DCMAKE_INSTALL_PREFIX=/thirdparty_build \
  -DEVENT__DISABLE_OPENSSL:BOOL=on \
  -DEVENT__DISABLE_REGRESS:BOOL=on \
  -DCMAKE_BUILD_TYPE=Debug \
  -DEVENT__DISABLE_TESTS:BOOL=on \
  -DEVENT__DISABLE_SAMPLES:BOOL=on \
  -DEVENT__DISABLE_BENCHMARK:BOOL=on \
  ..

make -j;make install

cd /source
./ci/do_ci.sh bazel.release.server_only


cd /source