
include(${SEL4_TUTORIALS_DIR}/settings.cmake)
sel4_tutorials_regenerate_tutorial(${CMAKE_CURRENT_SOURCE_DIR})

cmake_minimum_required(VERSION 3.7.2)

project(hello-camkes-0 C ASM)

find_package(camkes-tool REQUIRED)
camkes_tool_setup_camkes_build_environment()

DeclareCAmkESComponent(Client SOURCES client.c)

DeclareCAmkESRootserver(hello.camkes)

GenerateCAmkESRootserver()

# utility CMake functions for the tutorials (not required in normal, non-tutorial applications)
set(FINISH_COMPLETION_TEXT "Hello CAmkES World")
set(START_COMPLETION_TEXT "Hello CAmkES World")
configure_file(${SEL4_TUTORIALS_DIR}/tools/expect.py ${CMAKE_BINARY_DIR}/check @ONLY)
include(simulation)
GenerateSimulateScript()

