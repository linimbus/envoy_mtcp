# envoy over mtcp

## envoy build docker

```
./ci/run_envoy_docker.sh './ci/do_ci.sh bazel.release.server_only'
```

## envoy build
```
cd /source
./ci/do_ci.sh bazel.release.server_only
```

## libevent build

```
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

```

## base centos7 1804

## install library

```
yum makecache
yum install -y gcc gcc-c++  kernel-devel kernel-headers kernel.x86_64 net-tools
yum install -y numactl-devel.x86_64 numactl-libs.x86_64
yum install -y libpcap.x86_64 libpcap-devel.x86_64
yum install -y pciutils
```

## clone mtcp

```
git clone https://github.com/eunyoung14/mtcp.git
```

## mtcp

```
bash setup_mtcp_env.sh
```

