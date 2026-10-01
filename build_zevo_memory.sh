#!/bin/bash
# Builds zevo_memory_mm_i386.so (32-bit) from zevo_memory.cpp.
# Usage: put this script next to zevo_memory.cpp, then:  bash build_zevo_memory.sh
set -e

# 1. 32-bit toolchain (Debian/Ubuntu)
if ! dpkg -s g++-multilib >/dev/null 2>&1; then
    sudo apt update && sudo apt install -y g++-multilib git
fi

# 2. Headers
[ -d metamod-r ] || git clone --depth 1 https://github.com/theAsmodai/metamod-r
[ -d rehlds ]    || git clone --depth 1 https://github.com/dreamstalker/rehlds

# 3. Build
SRC=zevo_memory.cpp
[ -f "$SRC" ] || SRC=zevo_memory__1_.cpp

g++ -m32 -O2 -shared -fPIC -std=gnu++11 -fno-exceptions -fno-rtti \
    -fno-stack-protector -fno-asynchronous-unwind-tables -D_FORTIFY_SOURCE=0 \
    -Dlinux -D__linux__ \
    -I rehlds/rehlds/common -I rehlds/rehlds/dlls -I rehlds/rehlds/engine \
    -I rehlds/rehlds/pm_shared -I rehlds/rehlds/public \
    -I metamod-r/metamod/src \
    "$SRC" -nodefaultlibs -Wl,--as-needed -lc \
    -o zevo_memory_mm_i386.so

file zevo_memory_mm_i386.so
echo "Done. Copy to cstrike/addons/zevo_memory/ and restart the server."
