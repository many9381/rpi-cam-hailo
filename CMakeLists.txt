cmake_minimum_required(VERSION 3.25)

project(camera_firmware LANGUAGES CXX ASM)

# Default to an optimized build with debug info when the caller did not pick a
# build type (an empty CMAKE_BUILD_TYPE compiles everything at -O0). Asserts
# stay enabled: -DNDEBUG is stripped so invariant checks behave exactly as in
# an unoptimized build. Pass -DCMAKE_BUILD_TYPE=Debug for an -O0 build.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
      Debug Release RelWithDebInfo MinSizeRel)
endif()
string(REPLACE "-DNDEBUG" "" CMAKE_CXX_FLAGS_RELWITHDEBINFO
    "${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")
string(REPLACE "-DNDEBUG" "" CMAKE_C_FLAGS_RELWITHDEBINFO
    "${CMAKE_C_FLAGS_RELWITHDEBINFO}")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Always emit compile_commands.json so clang-tidy (tools/ci/check.sh) can analyse
# every build directory without a separate configure.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(CTest)
include(cmake/Dependencies.cmake)
include(cmake/EmbedIntegrityPublicKey.cmake)

cf_embed_integrity_public_key(CF_INTEGRITY_TRUST_ANCHOR_SOURCE)

add_subdirectory(src/common)
add_subdirectory(src/ai)
add_subdirectory(src/config)
add_subdirectory(src/crypto)
add_subdirectory(src/integrity)
add_subdirectory(src/settings)
add_subdirectory(src/security)
add_subdirectory(src/boot)
add_subdirectory(src/media)
add_subdirectory(src/rtsp)
add_subdirectory(src/runtime)
add_subdirectory(src/service)
add_subdirectory(plugins/gst-secure-srtp)
add_subdirectory(web)
add_subdirectory(apps/camera-firmware)
add_subdirectory(apps/camera-firmware-integrity)
add_subdirectory(apps/rtsp-digest-credential)

if(BUILD_TESTING)
  add_subdirectory(tests)
endif()
