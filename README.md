# Sysrepo Provisioning plugin (DT)

## Introduction

This Sysrepo plugin is responsible for bridging OpenWrt [**ubus**](https://openwrt.org/docs/techref/ubus) running state data and Sysrepo/YANG datastore operational data related to provisioning.

## Development Setup

Setup the development environment using the provided [`setup-dev-sysrepo`](https://github.com/sartura/setup-dev-sysrepo) scripts. This will build all the necessary components and initialize a sparse OpenWrt filesystem.

Subsequent rebuilds of the plugin may be done by navigating to the plugin source directory and executing:

```
$ export SYSREPO_DIR=${HOME}/code/sysrepofs
$ cd ${SYSREPO_DIR}/repositories/plugins/provisioning-plugin

$ rm -rf ./build && mkdir ./build && cd ./build
$ cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
		-DCMAKE_PREFIX_PATH=${SYSREPO_DIR} \
		-DCMAKE_INSTALL_PREFIX=${SYSREPO_DIR} \
		-DCMAKE_BUILD_TYPE=Debug \
		..
-- The C compiler identification is GNU 9.3.0
-- Check for working C compiler: /usr/bin/cc
-- Check for working C compiler: /usr/bin/cc -- works
[...]
-- Configuring done
-- Generating done
-- Build files have been written to: ${SYSREPO_DIR}/repositories/plugins/provisioning-plugin/build

$ make && make install
[...]
[ 66%] Building C object CMakeFiles/sysrepo-plugin-dt-provisioning.dir/src/transform_data.c.o
[100%] Linking C executable sysrepo-plugin-dt-provisioning
[100%] Built target sysrepo-plugin-dt-provisioning
[100%] Built target sysrepo-plugin-dt-provisioning
Install the project...
-- Install configuration: "Debug"
-- Installing: ${SYSREPO_DIR}/bin/sysrepo-plugin-dt-provisioning
-- Set runtime path of "${SYSREPO_DIR}/bin/sysrepo-plugin-dt-provisioning" to ""

$ cd ..
```

Before using the plugin it is necessary to install relevant YANG modules. For this particular plugin, the following commands need to be invoked:

```
$ cd ${SYSREPO_DIR}/repositories/plugins/dhcp
$ export LD_LIBRARY_PATH="${SYSREPO_DIR}/lib64;${SYSREPO_DIR}/lib"
$ export PATH="${SYSREPO_DIR}/bin:${PATH}"

$ sysrepoctl -i ./yang/terastream-provisioning@2018-05-14.yang
```

## YANG Overview

The `terastream-provisioning` YANG module with the `ts-ps` prefix consists of the following `operational` state data:

* `/terastream-provisioning:hgw-diagnostics` — operational data with hardware information

## Running and Examples

This plugin is installed as the `sysrepo-plugin-dt-provisioning` binary to `${SYSREPO_DIR}/bin/` directory path. Simply invoke this binary, making sure that the environment variables are set correctly:

```
$ sysrepo-plugin-dt-provisioning
[INF]: Applying scheduled changes.
[INF]: File "terastream-provisioning@2018-05-14.yang" was installed.
[INF]: Module "terastream-provisioning" was installed.
[INF]: Scheduled changes applied.
[INF]: Session 20 (user "...") created.
[INF]: plugin: start session to startup datastore
[INF]: Session 21 (user "...") created.
[INF]: plugin: plugin init done
[...]
```

Output from the plugin is expected; since the plugin nor the YANG module define configurational state data there are no `startup` or `running` datastore operations. We can confirm this by invoking the following commands:

```
$ sysrepocfg -X -d startup -f json -m 'terastream-provisioning'
{
}

$ sysrepocfg -X -d running -f json -m 'terastream-provisioning'
{
}
```

Using `sysrepocfg` we can access `operational` state data which is gathered by the plugin over [ubus](). Here is an example data output:

```
$ sysrepocfg -X -d operational -f json -x '/terastream-provisioning:hgw-diagnostics'
{
  "terastream-provisioning:hgw-diagnostics": {
    "name": "Generic Platform Name",
    "board-id": "KG328",
    "hardware": "KG328",
    "model": "KG328X",
    "cpu-usage": 4,
    "memory-status": 45,
    "disk-usage": 19,
    "version-other-bank": "KG328-X-GENERIC-NEW-4.2.0ALPHA1-180417_1237",
    "version-running-bank": "KG328-X-GENERIC-NEW-4.2.0ALPHA1-180418_0817"
  }
}
```