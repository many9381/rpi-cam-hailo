add_library(camera_firmware_boot
    FirmwareBootCoordinator.cpp
)

target_include_directories(camera_firmware_boot
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(camera_firmware_boot
    PUBLIC
        camera_firmware_common
        camera_firmware_security
)
