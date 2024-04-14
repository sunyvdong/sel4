set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)
set(CMAKE_SKIP_RPATH TRUE)
set(CMAKE_C_COMPILER "arm-linux-gnueabi-gcc")
set(CMAKE_LINK "arm-linux-gnueabi-gcc")
set(CMAKE_SIZE "arm-linux-gnueabi-size")
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
set(CMAKE_C_COMPILER_FORCED ON)

# 编译选项设置
set(COMPILE_OPTIONS_FLAG -march=armv7-a -marm  -D__KERNEL_32__ -g -nostdinc -fno-pic -fno-pie -fno-stack-protector -fno-asynchronous-unwind-tables -ftls-model=local-exec -mtp=soft -mno-unaligned-access -mfloat-abi=softfp -std=gnu11 -ffunction-sections -fdata-sections)

# 链接选项设置
set(LINK_OPTIONS_FLAG "-march=armv7-a -D__KERNEL_32__   -static -nostdlib -z max-page-size=0x1000    -Wl,-u_sel4_start -Wl,-e_sel4_start  -Wl,--gc-section")
