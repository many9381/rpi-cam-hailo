add_executable(camera-firmware
    main.cpp
)

target_link_libraries(camera-firmware
    PRIVATE
        camera_firmware_config
        camera_firmware_media
        camera_firmware_ai
        camera_firmware_rtsp
        camera_firmware_service
)

target_compile_definitions(camera-firmware
    PRIVATE
        CF_SECURE_SRTP_PLUGIN_DIR="$<TARGET_FILE_DIR:gstcfsecuresrtp>"
)

add_dependencies(camera-firmware gstcfsecuresrtp)
