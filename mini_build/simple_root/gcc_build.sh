#!/bin/bash


rm -rf build
mkdir build
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE="./arm_gcc_toolchain.cmake" -Dcase_name=tutorial -Dtutorials=/home/sunyvdong/sel4/mini_build/sel4-tutorials-manifest
make