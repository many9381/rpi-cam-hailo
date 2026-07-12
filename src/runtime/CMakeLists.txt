add_library(camera_firmware_runtime
    FirmwareRuntime.cpp
)

target_include_directories(camera_firmware_runtime
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(camera_firmware_runtime
    PUBLIC
        camera_firmware_ai
        camera_firmware_common
        camera_firmware_config
        camera_firmware_media
        camera_firmware_rtsp
)
