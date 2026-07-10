include_guard(GLOBAL)

find_package(PkgConfig REQUIRED)
find_package(OpenSSL 3.0 REQUIRED)
find_package(JPEG REQUIRED)
find_package(SQLite3 3.31 REQUIRED)
find_package(yaml-cpp REQUIRED)
if(POLICY CMP0153)
  cmake_policy(PUSH)
  # Drogon's installed FindJsoncpp.cmake still uses exec_program() under CMake 3.31.
  cmake_policy(SET CMP0153 OLD)
endif()
find_package(Drogon REQUIRED)
if(POLICY CMP0153)
  cmake_policy(POP)
endif()

pkg_check_modules(GSTREAMER REQUIRED IMPORTED_TARGET gstreamer-1.0)
pkg_check_modules(GSTREAMER_APP REQUIRED IMPORTED_TARGET gstreamer-app-1.0)
pkg_check_modules(GSTREAMER_RTSP_SERVER REQUIRED IMPORTED_TARGET gstreamer-rtsp-server-1.0)
pkg_check_modules(GIO REQUIRED IMPORTED_TARGET gio-2.0)
pkg_check_modules(LIBSRTP2 REQUIRED IMPORTED_TARGET libsrtp2>=2.7.0)
pkg_check_modules(LIBCAMERA REQUIRED IMPORTED_TARGET libcamera)
pkg_check_modules(X264 REQUIRED IMPORTED_TARGET x264)

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
