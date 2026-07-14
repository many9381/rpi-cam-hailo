include_guard(GLOBAL)

find_package(PkgConfig REQUIRED)
find_package(OpenSSL 3.0 REQUIRED)
find_package(JPEG REQUIRED)
find_package(SQLite3 3.31 REQUIRED)
find_package(yaml-cpp REQUIRED)

set(CAMERA_FIRMWARE_DROGON_SOURCE_DIR "" CACHE PATH
    "Read-only path to the exact Drogon 1.9.0 source tree")
set(_cf_drogon_patch
    "${CMAKE_CURRENT_LIST_DIR}/../patches/drogon-1.9.0-preserve-raw-cookie-headers.patch")

function(_cf_drogon_tree_digest root output_variable)
  file(GLOB_RECURSE _cf_tree_files
      LIST_DIRECTORIES false
      RELATIVE "${root}"
      "${root}/*")
  list(SORT _cf_tree_files)
  set(_cf_tree_manifest "")
  foreach(_cf_tree_file IN LISTS _cf_tree_files)
    if(_cf_tree_file STREQUAL ".camera-firmware-patch" OR
        _cf_tree_file STREQUAL "lib/inc/drogon/version.h")
      continue()
    endif()
    set(_cf_tree_path "${root}/${_cf_tree_file}")
    if(IS_SYMLINK "${_cf_tree_path}")
      file(READ_SYMLINK "${_cf_tree_path}" _cf_tree_link)
      string(APPEND _cf_tree_manifest
          "symlink|${_cf_tree_file}|${_cf_tree_link}\n")
    else()
      file(SHA256 "${_cf_tree_path}" _cf_tree_sha256)
      string(APPEND _cf_tree_manifest
          "file|${_cf_tree_file}|${_cf_tree_sha256}\n")
    endif()
  endforeach()
  string(SHA256 _cf_tree_digest "${_cf_tree_manifest}")
  set(${output_variable} "${_cf_tree_digest}" PARENT_SCOPE)
endfunction()

if(CAMERA_FIRMWARE_DROGON_SOURCE_DIR)
  get_filename_component(_cf_drogon_source
      "${CAMERA_FIRMWARE_DROGON_SOURCE_DIR}" REALPATH)
  set(_cf_drogon_expected_commit
      "f215cb15a0f53abd0ca7ee8b95ed8c9c3b40d262")
  set(_cf_drogon_expected_tree
      "4e355209ce0666e1892c00703307d0b098d71b9d")
  find_package(Git REQUIRED)
  execute_process(
      COMMAND "${GIT_EXECUTABLE}" -C "${_cf_drogon_source}"
              rev-parse --show-toplevel
      RESULT_VARIABLE _cf_drogon_git_root_result
      OUTPUT_VARIABLE _cf_drogon_git_root
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET)
  execute_process(
      COMMAND "${GIT_EXECUTABLE}" -C "${_cf_drogon_source}"
              rev-parse --verify HEAD
      RESULT_VARIABLE _cf_drogon_commit_result
      OUTPUT_VARIABLE _cf_drogon_commit
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET)
  execute_process(
      COMMAND "${GIT_EXECUTABLE}" -C "${_cf_drogon_source}"
              rev-parse --verify "HEAD^{tree}"
      RESULT_VARIABLE _cf_drogon_tree_result
      OUTPUT_VARIABLE _cf_drogon_tree
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET)
  get_filename_component(_cf_drogon_git_root "${_cf_drogon_git_root}" REALPATH)
  if(NOT _cf_drogon_git_root_result EQUAL 0 OR
      NOT _cf_drogon_commit_result EQUAL 0 OR
      NOT _cf_drogon_tree_result EQUAL 0 OR
      NOT _cf_drogon_git_root STREQUAL _cf_drogon_source OR
      NOT _cf_drogon_commit STREQUAL _cf_drogon_expected_commit OR
      NOT _cf_drogon_tree STREQUAL _cf_drogon_expected_tree)
    message(FATAL_ERROR
        "CAMERA_FIRMWARE_DROGON_SOURCE_DIR must be the exact clean official Drogon 1.9.0 Git source at commit ${_cf_drogon_expected_commit}")
  endif()
  execute_process(
      COMMAND "${GIT_EXECUTABLE}" -C "${_cf_drogon_source}"
              diff-files --quiet --ignore-submodules=all --
      RESULT_VARIABLE _cf_drogon_worktree_result)
  execute_process(
      COMMAND "${GIT_EXECUTABLE}" -C "${_cf_drogon_source}"
              diff-index --cached --quiet --ignore-submodules=all HEAD --
      RESULT_VARIABLE _cf_drogon_index_result)
  if(NOT _cf_drogon_worktree_result EQUAL 0 OR
      NOT _cf_drogon_index_result EQUAL 0)
    message(FATAL_ERROR
        "CAMERA_FIRMWARE_DROGON_SOURCE_DIR must be the exact clean official Drogon 1.9.0 source; tracked files are modified")
  endif()

  find_program(_cf_patch_executable NAMES patch REQUIRED)
  set(_cf_drogon_copy
      "${CMAKE_BINARY_DIR}/_deps/camera-firmware-drogon-1.9.0-src")
  file(SHA256 "${_cf_drogon_patch}" _cf_drogon_patch_sha256)
  set(_cf_drogon_copy_identity
      "format=2\nresolved_source=${_cf_drogon_source}\ncommit=${_cf_drogon_commit}\ntree=${_cf_drogon_tree}\npatch_sha256=${_cf_drogon_patch_sha256}\n")
  set(_cf_drogon_stamp "${_cf_drogon_copy}/.camera-firmware-patch")
  set(_cf_drogon_copy_valid false)
  if(EXISTS "${_cf_drogon_stamp}")
    file(READ "${_cf_drogon_stamp}" _cf_existing_stamp)
    string(FIND "${_cf_existing_stamp}" "${_cf_drogon_copy_identity}"
        _cf_drogon_identity_position)
    if(_cf_drogon_identity_position EQUAL 0)
      string(REGEX MATCH "copy_tree_sha256=([0-9a-f]+)"
          _cf_drogon_copy_digest_match "${_cf_existing_stamp}")
      set(_cf_drogon_expected_copy_digest "${CMAKE_MATCH_1}")
      _cf_drogon_tree_digest("${_cf_drogon_copy}"
          _cf_drogon_actual_copy_digest)
      if(NOT _cf_drogon_expected_copy_digest STREQUAL
          _cf_drogon_actual_copy_digest)
        message(FATAL_ERROR
            "The copied patched Drogon 1.9.0 tree was modified; remove ${_cf_drogon_copy} and reconfigure")
      endif()
      set(_cf_drogon_copy_valid true)
    endif()
  endif()
  if(NOT _cf_drogon_copy_valid)
    file(REMOVE_RECURSE "${_cf_drogon_copy}")
    file(MAKE_DIRECTORY "${_cf_drogon_copy}")
    set(_cf_drogon_archive
        "${CMAKE_BINARY_DIR}/_deps/camera-firmware-drogon-1.9.0.tar")
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" -C "${_cf_drogon_source}"
                archive --format=tar --output "${_cf_drogon_archive}"
                "${_cf_drogon_commit}"
        RESULT_VARIABLE _cf_drogon_archive_result
        ERROR_VARIABLE _cf_drogon_archive_error)
    if(NOT _cf_drogon_archive_result EQUAL 0)
      message(FATAL_ERROR
          "Failed to archive exact Drogon 1.9.0 source: ${_cf_drogon_archive_error}")
    endif()
    execute_process(
        COMMAND "${CMAKE_COMMAND}" -E tar xf "${_cf_drogon_archive}"
        WORKING_DIRECTORY "${_cf_drogon_copy}"
        RESULT_VARIABLE _cf_drogon_extract_result
        ERROR_VARIABLE _cf_drogon_extract_error)
    file(REMOVE "${_cf_drogon_archive}")
    if(NOT _cf_drogon_extract_result EQUAL 0)
      message(FATAL_ERROR
          "Failed to extract exact Drogon 1.9.0 source: ${_cf_drogon_extract_error}")
    endif()
    execute_process(
        COMMAND "${_cf_patch_executable}" --batch --forward -p1
                --input "${_cf_drogon_patch}"
        WORKING_DIRECTORY "${_cf_drogon_copy}"
        RESULT_VARIABLE _cf_drogon_patch_result
        OUTPUT_VARIABLE _cf_drogon_patch_stdout
        ERROR_VARIABLE _cf_drogon_patch_stderr)
    if(NOT _cf_drogon_patch_result EQUAL 0)
      message(FATAL_ERROR
          "Failed to apply the project Drogon 1.9.0 patch:\n${_cf_drogon_patch_stdout}${_cf_drogon_patch_stderr}")
    endif()
    _cf_drogon_tree_digest("${_cf_drogon_copy}"
        _cf_drogon_patched_copy_digest)
    file(WRITE "${_cf_drogon_stamp}"
        "${_cf_drogon_copy_identity}copy_tree_sha256=${_cf_drogon_patched_copy_digest}\n")
  endif()

  set(BUILD_CTL OFF CACHE BOOL "" FORCE)
  set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
  set(BUILD_ORM OFF CACHE BOOL "" FORCE)
  set(BUILD_BROTLI OFF CACHE BOOL "" FORCE)
  set(BUILD_YAML_CONFIG OFF CACHE BOOL "" FORCE)
  set(USE_SUBMODULE OFF CACHE BOOL "" FORCE)
  set(_cf_project_build_testing "${BUILD_TESTING}")
  set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
  add_subdirectory("${_cf_drogon_copy}"
                   "${CMAKE_BINARY_DIR}/_deps/camera-firmware-drogon-1.9.0-build"
                   EXCLUDE_FROM_ALL)
  set(BUILD_TESTING "${_cf_project_build_testing}" CACHE BOOL "" FORCE)
  add_library(Drogon::Drogon ALIAS drogon)
  set(Drogon_VERSION "1.9.0")
  message(STATUS
      "Drogon 1.9.0: official commit ${_cf_drogon_commit}, tree ${_cf_drogon_tree}, patch ${_cf_drogon_patch_sha256}, source ${_cf_drogon_source}, copy ${_cf_drogon_copy}")
else()
  if(POLICY CMP0153)
    cmake_policy(PUSH)
    # Drogon's installed FindJsoncpp.cmake still uses exec_program() under CMake 3.31.
    cmake_policy(SET CMP0153 OLD)
  endif()
  find_package(Drogon 1.9.0 EXACT CONFIG REQUIRED)
  if(POLICY CMP0153)
    cmake_policy(POP)
  endif()

  include(CheckCXXSourceCompiles)
  set(_cf_saved_required_libraries "${CMAKE_REQUIRED_LIBRARIES}")
  set(CMAKE_REQUIRED_LIBRARIES Drogon::Drogon)
  unset(CAMERA_FIRMWARE_HAS_PATCHED_DROGON_1_9_0 CACHE)
  check_cxx_source_compiles([[
    #include <drogon/HttpRequest.h>
    #ifndef DROGON_CAMERA_FIRMWARE_RAW_COOKIE_HEADERS
    #error "camera-firmware raw Cookie patch is absent"
    #endif
    int main() {
      return drogon::cameraFirmwareRawCookiePatchVersion() == 2U ? 0 : 1;
    }
  ]] CAMERA_FIRMWARE_HAS_PATCHED_DROGON_1_9_0)
  set(CMAKE_REQUIRED_LIBRARIES "${_cf_saved_required_libraries}")
  if(NOT CAMERA_FIRMWARE_HAS_PATCHED_DROGON_1_9_0)
    message(FATAL_ERROR
        "Drogon 1.9.0 is unpatched or incompatible. Install the exact project-patched build or configure with -DCAMERA_FIRMWARE_DROGON_SOURCE_DIR=/path/to/exact/drogon-1.9.0")
  endif()
  message(STATUS "Drogon 1.9.0: exact compatible patched installation")
endif()

pkg_check_modules(GSTREAMER REQUIRED IMPORTED_TARGET gstreamer-1.0)
pkg_check_modules(GSTREAMER_APP REQUIRED IMPORTED_TARGET gstreamer-app-1.0)
pkg_check_modules(GSTREAMER_RTSP_SERVER REQUIRED IMPORTED_TARGET gstreamer-rtsp-server-1.0)
pkg_check_modules(GIO REQUIRED IMPORTED_TARGET gio-2.0)
pkg_check_modules(LIBSRTP2 REQUIRED IMPORTED_TARGET libsrtp2>=2.7.0)
pkg_check_modules(LIBCAMERA REQUIRED IMPORTED_TARGET libcamera)
pkg_check_modules(X264 REQUIRED IMPORTED_TARGET x264)
pkg_check_modules(LIBSWSCALE REQUIRED IMPORTED_TARGET libswscale)
pkg_check_modules(LIBAVUTIL REQUIRED IMPORTED_TARGET libavutil)

find_path(HAILORT_INCLUDE_DIR
    NAMES hailo/hailort.h hailo/vdevice.hpp hailo/infer_model.hpp
)
find_library(HAILORT_LIBRARY
    NAMES hailort
)
if(HAILORT_INCLUDE_DIR AND HAILORT_LIBRARY)
  set(CF_TEST_EXPECT_HAILORT ON)
  if(NOT TARGET HailoRT::HailoRT)
    add_library(HailoRT::HailoRT UNKNOWN IMPORTED)
    set_target_properties(HailoRT::HailoRT
        PROPERTIES
            IMPORTED_LOCATION "${HAILORT_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${HAILORT_INCLUDE_DIR}"
    )
  endif()
endif()
