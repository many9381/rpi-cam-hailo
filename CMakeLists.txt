cmake_minimum_required(VERSION 3.31)

project(camera_firmware LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CTest)
include(cmake/Dependencies.cmake)

add_subdirectory(src/common)
add_subdirectory(src/config)
add_subdirectory(src/media)

if(BUILD_TESTING)
  add_subdirectory(tests)
endif()
