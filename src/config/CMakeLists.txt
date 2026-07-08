add_library(camera_firmware_config STATIC
    AppConfig.cpp
)

target_include_directories(camera_firmware_config
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(camera_firmware_config
    PUBLIC
        camera_firmware_common
        yaml-cpp::yaml-cpp
)
