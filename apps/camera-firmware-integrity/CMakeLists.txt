add_executable(camera-firmware-integrity
    main.cpp
)

target_link_libraries(camera-firmware-integrity
    PRIVATE
        camera_firmware_integrity_signer
)
