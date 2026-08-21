#!/bin/bash
set -e

BUILD_DIR="build"
BUILD_TYPE="Release"
EXTRA_FLAGS=""

case "$1" in
  debug)
    BUILD_TYPE="Debug"
    ;;
  asan)
    # Separate build dir: the sanitized binary is much slower and should not
    # replace the one the API shells out to.
    BUILD_DIR="build-asan"
    BUILD_TYPE="Debug"
    # UBSan matters as much as ASan here -- the extractors parse
    # attacker-controlled length fields, where the first symptom of a bad
    # bounds check is usually an overflowed offset rather than a wild read.
    EXTRA_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all -g"
    ;;
  "")
    ;;
  *)
    echo "usage: $0 [debug|asan]" >&2
    exit 2
    ;;
esac

echo "Building DPI Engine (${BUILD_TYPE}${EXTRA_FLAGS:+ +sanitizers})..."

mkdir -p ${BUILD_DIR}
cd ${BUILD_DIR}

cmake -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
      -DCMAKE_CXX_FLAGS="${EXTRA_FLAGS}" \
      -DCMAKE_EXE_LINKER_FLAGS="${EXTRA_FLAGS}" \
      ..
make -j$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)

echo "Build complete: ${BUILD_DIR}/bin/dpi_engine"
