cmake_minimum_required(VERSION 3.25)

if(NOT DEFINED CF_PROJECT_SOURCE_DIR OR
        "${CF_PROJECT_SOURCE_DIR}" STREQUAL "")
    message(FATAL_ERROR
        "NodeVersionTest requires -DCF_PROJECT_SOURCE_DIR=<value>")
endif()

include("${CF_PROJECT_SOURCE_DIR}/web/NodeVersion.cmake")

foreach(CF_VERSION IN ITEMS 20.19.0 20.99.0 22.12.0 23.0.0)
    cf_node_version_is_supported("${CF_VERSION}" CF_SUPPORTED)
    if(NOT CF_SUPPORTED)
        message(FATAL_ERROR
            "expected Node.js ${CF_VERSION} to be supported")
    endif()
endforeach()

foreach(CF_VERSION IN ITEMS 20.18.99 21.0.0 21.99.0 22.11.99 invalid)
    cf_node_version_is_supported("${CF_VERSION}" CF_SUPPORTED)
    if(CF_SUPPORTED)
        message(FATAL_ERROR
            "expected Node.js ${CF_VERSION} to be rejected")
    endif()
endforeach()

message(STATUS "Node.js version boundaries passed")
