cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(controlflowpatch)

set(HEADLESS 1)

file(GLOB SOURCES
	*.cpp
	*.c
	*.h)

add_library(controlflowpatch SHARED ${SOURCES})

if(NOT BN_API_BUILD_EXAMPLES AND NOT BN_INTERNAL_BUILD)
    # Out-of-tree build
    find_path(
        BN_API_PATH
        NAMES binaryninjaapi.h
        HINTS ../../binaryninja-api $ENV{BN_API_PATH}
        REQUIRED
    )
    add_subdirectory(${BN_API_PATH} api)
endif()

target_link_libraries(controlflowpatch binaryninjaapi)

set_target_properties(controlflowpatch PROPERTIES
	CXX_STANDARD 17
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
	C_STANDARD 99
	C_STANDARD_REQUIRED ON
	C_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON)

bn_install_plugin(controlflowpatch)

if(BN_INTERNAL_BUILD)
	plugin_rpath(controlflowpatch)
	set_target_properties(controlflowpatch PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
		RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
endif()
