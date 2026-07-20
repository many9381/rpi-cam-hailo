function(camera_firmware_add_application target)
    add_executable(${target}
        main.cpp
    )

    target_link_libraries(${target}
        PRIVATE
            camera_firmware_boot
            camera_firmware_config
            camera_firmware_media
            camera_firmware_ai
            camera_firmware_rtsp
            camera_firmware_runtime
            camera_firmware_service
    )

    target_compile_definitions(${target}
        PRIVATE
            CF_SECURE_SRTP_PLUGIN_DIR="$<TARGET_FILE_DIR:gstcfsecuresrtp>"
    )

    add_dependencies(${target}
        camera_firmware_web
        gstcfsecuresrtp
    )
endfunction()

camera_firmware_add_application(camera-firmware)

if(BUILD_TESTING)
    camera_firmware_add_application(camera-firmware-integration)
    target_compile_definitions(camera-firmware-integration
        PRIVATE
            CAMERA_FIRMWARE_TEST_INTEGRITY_TRUST_ANCHOR=1
            CAMERA_FIRMWARE_TEST_PROTECTION_RUNTIME_PROBE=1
    )
endif()
