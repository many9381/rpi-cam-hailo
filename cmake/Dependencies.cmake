include_guard(GLOBAL)

find_package(PkgConfig REQUIRED)
find_package(OpenSSL)
find_package(yaml-cpp REQUIRED)

pkg_check_modules(GSTREAMER REQUIRED IMPORTED_TARGET gstreamer-1.0)
pkg_check_modules(LIBSRTP2 REQUIRED IMPORTED_TARGET libsrtp2>=2.7.0)
