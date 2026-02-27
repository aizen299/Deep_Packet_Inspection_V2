#!/bin/bash
set -e

BUILD_DIR="build"
BUILD_TYPE="Release"

if [ "$1" == "debug" ]; then
  BUILD_TYPE="Debug"
fi

echo "Building DPI Engine (${BUILD_TYPE})..."

mkdir -p ${BUILD_DIR}
cd ${BUILD_DIR}

cmake -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ..
make -j$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)

echo "Build complete."