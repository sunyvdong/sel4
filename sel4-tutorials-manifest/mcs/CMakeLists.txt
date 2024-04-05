
#
# Copyright 2018, Data61, CSIRO (ABN 41 687 119 230)
#
# SPDX-License-Identifier: BSD-2-Clause
#
include(${SEL4_TUTORIALS_DIR}/settings.cmake)
sel4_tutorials_regenerate_tutorial(${CMAKE_CURRENT_SOURCE_DIR})

cmake_minimum_required(VERSION 3.7.2)
project(mcs C ASM)

set(KernelIsMCS ON CACHE STRING "" FORCE)
sel4_tutorials_setup_capdl_tutorial_environment()


cdl_pp(${CMAKE_CURRENT_SOURCE_DIR}/.manifest.obj cdl_pp_target
	
    ELF "spinner"
    CFILE "${CMAKE_CURRENT_BINARY_DIR}/cspace_spinner.c"
    
    ELF "sender"
    CFILE "${CMAKE_CURRENT_BINARY_DIR}/cspace_sender.c"
    
    ELF "server"
    CFILE "${CMAKE_CURRENT_BINARY_DIR}/cspace_server.c"
    
    ELF "mcs"
    CFILE "${CMAKE_CURRENT_BINARY_DIR}/cspace_mcs.c"
    
)   


add_executable(spinner EXCLUDE_FROM_ALL spinner.c cspace_spinner.c)
add_dependencies(spinner cdl_pp_target)
target_link_libraries(spinner sel4tutorials)

list(APPEND elf_files "$<TARGET_FILE:spinner>")
list(APPEND elf_targets "spinner")


add_executable(sender EXCLUDE_FROM_ALL sender.c cspace_sender.c)
add_dependencies(sender cdl_pp_target)
target_link_libraries(sender sel4tutorials)

list(APPEND elf_files "$<TARGET_FILE:sender>")
list(APPEND elf_targets "sender")


add_executable(server EXCLUDE_FROM_ALL server.c cspace_server.c)
add_dependencies(server cdl_pp_target)
target_link_libraries(server sel4tutorials)

list(APPEND elf_files "$<TARGET_FILE:server>")
list(APPEND elf_targets "server")


add_executable(mcs EXCLUDE_FROM_ALL mcs.c cspace_mcs.c)
add_dependencies(mcs cdl_pp_target)
target_link_libraries(mcs sel4tutorials)

list(APPEND elf_files "$<TARGET_FILE:mcs>")
list(APPEND elf_targets "mcs")




cdl_ld("${CMAKE_CURRENT_BINARY_DIR}/spec.cdl" capdl_spec 
    MANIFESTS ${CMAKE_CURRENT_SOURCE_DIR}/.allocator.obj
    ELF ${elf_files}
    KEYS ${elf_targets}
    DEPENDS ${elf_targets})

DeclareCDLRootImage("${CMAKE_CURRENT_BINARY_DIR}/spec.cdl" capdl_spec ELF ${elf_files} ELF_DEPENDS ${elf_targets})


set(FINISH_COMPLETION_TEXT "
Yield
Yield
Yield")
set(START_COMPLETION_TEXT "
Yield
Yield
Yield")
configure_file(${SEL4_TUTORIALS_DIR}/tools/expect.py ${CMAKE_BINARY_DIR}/check @ONLY)
include(simulation)
GenerateSimulateScript()
