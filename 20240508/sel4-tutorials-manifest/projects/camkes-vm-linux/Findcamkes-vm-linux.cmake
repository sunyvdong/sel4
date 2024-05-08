#
# Copyright 2019, Data61, CSIRO (ABN 41 687 119 230)
#
# SPDX-License-Identifier: BSD-2-Clause
#

set(CAMKES_VM_LINUX_DIR "${CMAKE_CURRENT_LIST_DIR}" CACHE STRING "")
set(CAMKES_VM_LINUX_HELPERS_PATH "${CMAKE_CURRENT_LIST_DIR}/vm-linux-helpers.cmake" CACHE STRING "")
set(
    CAMKES_VM_LINUX_MODULE_HELPERS_PATH "${CMAKE_CURRENT_LIST_DIR}/linux-module-helpers.cmake"
    CACHE STRING ""
)
set(
    CAMKES_VM_LINUX_SOURCE_HELPERS_PATH "${CMAKE_CURRENT_LIST_DIR}/linux-source-helpers.cmake"
    CACHE STRING ""
)
mark_as_advanced(
    CAMKES_VM_LINUX_DIR
    CAMKES_VM_LINUX_HELPERS_PATH
    CAMKES_VM_LINUX_MODULE_HELPERS_PATH
    CAMKES_VM_LINUX_SOURCE_HELPERS_PATH
)

macro(camkes_vm_linux_import_project)
    add_subdirectory("${CAMKES_VM_LINUX_DIR}" camkes-vm-linux)
endmacro()

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(
    camkes-vm-linux
    DEFAULT_MSG
    CAMKES_VM_LINUX_DIR
    CAMKES_VM_LINUX_HELPERS_PATH
    CAMKES_VM_LINUX_MODULE_HELPERS_PATH
    CAMKES_VM_LINUX_SOURCE_HELPERS_PATH
)