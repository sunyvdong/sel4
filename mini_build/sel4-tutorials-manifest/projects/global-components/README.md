<!--
     Copyright 2018, Data61, CSIRO (ABN 41 687 119 230)

     SPDX-License-Identifier: CC-BY-SA-4.0
-->
Global Components
=================

This repository contains a collection of reusable CAmkES components and 
interfaces.

cmake
-----

To include components and interfaces from this repository ensure that
`global-components.cmake` is included in your project.  An example is below.

```cmake
find_file(GLOBAL_COMPONENTS_PATH global-components.cmake PATHS ${CMAKE_SOURCE_DIR}/projects/global-components/ CMAKE_FIND_ROOT_PATH_BOTH)
mark_as_advanced(FORCE GLOBAL_COMPONENTS_PATH)
if("${GLOBAL_COMPONENTS_PATH}" STREQUAL "GLOBAL_COMPONENTS_PATH-NOTFOUND")
    message(FATAL_ERROR "Failed to find global-components.cmake. Consider cmake -DGLOBAL_COMPONENTS_PATH=/path/to/global-components.cmake")
endif()
include(${GLOBAL_COMPONENTS_PATH})
```
