cmake_minimum_required(VERSION 2.8.12.2)
set(UNAME sel4_app)
set(R_CUR_DIR ${CMAKE_CURRENT_SOURCE_DIR})

# 设置工程名 语言为c和汇编
project(${UNAME} C ASM)

message("case_name=${case_name} tutorials=${tutorials}")

set(header_inc 
        ${tutorials}/projects/sel4runtime/include
        ${tutorials}/projects/sel4runtime/include/mode/32
        ${tutorials}/projects/sel4runtime/include/arch/arm
        ${tutorials}/projects/sel4runtime/include/sel4_arch/aarch32
        ${tutorials}/${case_name}_build/sel4runtime/gen_config
        ${tutorials}/kernel/libsel4/include
        ${tutorials}/kernel/libsel4/arch_include/arm
        ${tutorials}/kernel/libsel4/sel4_arch_include/aarch32
        ${tutorials}/kernel/libsel4/sel4_plat_include/zynq7000
        ${tutorials}/kernel/libsel4/mode_include/32
        ${tutorials}/${case_name}_build/libsel4/include
        ${tutorials}/${case_name}_build/libsel4/arch_include/arm
        ${tutorials}/${case_name}_build/libsel4/sel4_arch_include/aarch32
        ${tutorials}/${case_name}_build/libsel4/autoconf
        ${tutorials}/${case_name}_build/libsel4/gen_config
        ${tutorials}/${case_name}_build/kernel/gen_config)

include_directories(${header_inc})

set(LINK_SCRIPT "${tutorials}/tools/seL4/cmake-tool/helpers/tls_rootserver.lds")
set(CMAKE_C_LINK_FLAGS "${LINK_OPTIONS_FLAG},-Map=${UNAME}.map")

set(ELF_NAME ${UNAME}.elf)
add_executable(${ELF_NAME} ${R_CUR_DIR}/main.c)
target_compile_options(${ELF_NAME} PRIVATE ${COMPILE_OPTIONS_FLAG})

set(ext_lib
	${tutorials}/${case_name}_build/libsel4/libsel4.a
	${tutorials}/${case_name}_build/sel4runtime/libsel4runtime.a
	${tutorials}/${case_name}_build/musllibc/build-temp/lib/libxnet.a
	${tutorials}/${case_name}_build/musllibc/build-temp/lib/libcrypt.a
	${tutorials}/${case_name}_build/musllibc/build-temp/lib/libpthread.a
	${tutorials}/${case_name}_build/musllibc/build-temp/lib/libresolv.a
	${tutorials}/${case_name}_build/musllibc/build-temp/lib/libm.a
	${tutorials}/${case_name}_build/musllibc/build-temp/lib/libc.a
	${tutorials}/${case_name}_build/musllibc/build-temp/lib/libdl.a
	${tutorials}/${case_name}_build/musllibc/build-temp/lib/librt.a
	${tutorials}/${case_name}_build/musllibc/build-temp/lib/libutil.a)

#链接
target_link_libraries(${ELF_NAME} ${ext_lib} -T${LINK_SCRIPT} -lgcc)

#输出段信息
add_custom_command(TARGET ${ELF_NAME} POST_BUILD COMMAND ${CMAKE_SIZE} --format=sysv --totals ${ELF_NAME})

#生成hex
add_custom_command(TARGET ${ELF_NAME} POST_BUILD COMMAND ${CMAKE_OBJCOPY} -O ihex "${ELF_NAME}" "${UNAME}.hex")

#生成反汇编
add_custom_command(TARGET ${ELF_NAME} POST_BUILD COMMAND ${CMAKE_OBJDUMP} -S -D "${ELF_NAME}" > "${UNAME}.txt")

#生成bin文件
add_custom_command(TARGET ${ELF_NAME} POST_BUILD COMMAND ${CMAKE_OBJCOPY} -O binary "${ELF_NAME}" "${UNAME}.bin")
