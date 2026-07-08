add_library(gstcfsecuresrtp MODULE
    gstcfsecuresrtpenc.cpp
)

set_target_properties(gstcfsecuresrtp
    PROPERTIES
        PREFIX ""
        LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/plugins/gst-secure-srtp"
)

target_include_directories(gstcfsecuresrtp
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(gstcfsecuresrtp
    PRIVATE
        camera_firmware_common
        camera_firmware_rtsp
        PkgConfig::GSTREAMER
        PkgConfig::LIBSRTP2
)

target_compile_definitions(gstcfsecuresrtp
    PRIVATE
        PACKAGE="camera-firmware"
)
