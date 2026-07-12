cmake_minimum_required(VERSION 3.25)

project(camera_firmware LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CTest)
include(cmake/Dependencies.cmake)

add_subdirectory(src/common)
add_subdirectory(src/ai)
add_subdirectory(src/config)
add_subdirectory(src/security)
add_subdirectory(src/boot)
add_subdirectory(src/media)
add_subdirectory(src/rtsp)
add_subdirectory(src/runtime)
add_subdirectory(src/service)
add_subdirectory(plugins/gst-secure-srtp)
add_subdirectory(web)
add_subdirectory(apps/camera-firmware)
add_subdirectory(apps/rtsp-digest-credential)

if(BUILD_TESTING)
  add_subdirectory(tests)
endif()
