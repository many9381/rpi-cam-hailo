add_executable(rtsp-digest-credential
    main.cpp
)

target_link_libraries(rtsp-digest-credential
    PRIVATE
        camera_firmware_rtsp
)
