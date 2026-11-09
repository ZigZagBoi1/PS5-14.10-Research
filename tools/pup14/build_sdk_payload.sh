#!/usr/bin/env bash
set -euo pipefail

src="$(cd "$(dirname "$0")/../.." && pwd)"
build=/root/pup14-sdk-build
mkdir -p "$build"
upstream="$src/artifacts/pup14/upstream-inspect"
if [[ ! -d "$upstream/.git" ]] ||
   [[ "$(git -C "$upstream" rev-parse HEAD)" != 290f5dd216b6878223457f51b32127acc480964a ]]; then
  upstream=/root/pup14-sdk-upstream
  if [[ ! -d "$upstream/.git" ]]; then
    git clone --quiet https://github.com/zecoxao/ps5-pup-decrypt.git "$upstream"
  fi
  git -C "$upstream" checkout --quiet 290f5dd216b6878223457f51b32127acc480964a
fi
cp -a "$upstream/." "$build/"
cp "$src/tools/pup14/network/sdk_main.c" "$build/source/main.c"
cp "$src/tools/pup14/network/sdk_decrypt.c" "$build/source/decrypt.c"
cp "$src/tools/pup14/network/sdk_encryptsrv.c" "$build/source/encryptsrv.c"
cp "$src/tools/pup14/network/decryptio.c" "$build/source/decryptio.c"
cp "$src/tools/pup14/network/research_net.c" "$build/source/research_net.c"
cp "$src/tools/pup14/network/sdk_debug.h" "$build/include/debug.h"
cp "$src/tools/pup14/network/sdk_defines.h" "$build/include/defines.h"
cp "$src/tools/pup14/network/research_net.h" "$build/include/research_net.h"
cp "$src/tools/pup14/network/sdk_wrapper.c" "$build/source/"
cd "$build"
/opt/ps5-payload-sdk/bin/prospero-clang -fcommon -c source/sdk_wrapper.c -o sdk_wrapper.o
/opt/ps5-payload-sdk/bin/prospero-clang -I. -Iinclude -fcommon \
  sdk_wrapper.o source/main.c source/decrypt.c source/decryptio.c \
  source/encryptsrv.c source/research_net.c \
  -o "$src/artifacts/pup14/PS5_1410_RESEARCH_LAN_SDK.elf"
