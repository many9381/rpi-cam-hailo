add_library(camera_firmware_rtsp STATIC
    SrtpSessionKey.cpp
)

set_target_properties(camera_firmware_rtsp
    PROPERTIES
        POSITION_INDEPENDENT_CODE ON
)

target_include_directories(camera_firmware_rtsp
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(camera_firmware_rtsp
    PUBLIC
        camera_firmware_common
)
