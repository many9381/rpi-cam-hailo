add_library(camera_firmware_ai STATIC
    AiModelRunner.cpp
    AiRuntime.cpp
    AiFrameTap.cpp
    DetectionBus.cpp
)

set_target_properties(camera_firmware_ai
    PROPERTIES
        POSITION_INDEPENDENT_CODE ON
)

target_include_directories(camera_firmware_ai
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(camera_firmware_ai
    PUBLIC
        camera_firmware_media
)
