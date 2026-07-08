add_library(camera_firmware_ai STATIC
    AiFramePump.cpp
    AiModelProcessor.cpp
    AiModelRunner.cpp
    AiRuntime.cpp
    AiFrameTap.cpp
    DetectionBus.cpp
    YoloPostprocess.cpp
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

if(TARGET HailoRT::HailoRT)
    target_sources(camera_firmware_ai
        PRIVATE
            HailoBackend.cpp
    )
    target_compile_definitions(camera_firmware_ai
        PUBLIC
            CF_HAVE_HAILORT=1
    )
    target_link_libraries(camera_firmware_ai
        PRIVATE
            HailoRT::HailoRT
    )
endif()
