include_guard(GLOBAL)

find_package(PkgConfig REQUIRED)
find_package(OpenSSL)
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
pkg_check_modules(LIBSRTP2 REQUIRED IMPORTED_TARGET libsrtp2>=2.7.0)
