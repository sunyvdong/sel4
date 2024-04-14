#!/bin/bash

cd ../sel4-tutorials-manifest/tutorial_build/
cp ../../simple_root/build/sel4_app.elf capabilities
rm elfloader/archive.*
rm elfloader/elfloader
rm images/capabilities-image-arm-zynq7000
ninja images/capabilities-image-arm-zynq7000
./simulate -d 
