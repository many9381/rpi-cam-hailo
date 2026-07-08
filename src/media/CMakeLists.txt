add_library(camera_firmware_media STATIC
    EncodedRing.cpp
    FrameLease.cpp
    SnapshotTap.cpp
)

target_include_directories(camera_firmware_media
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(camera_firmware_media
    PUBLIC
        camera_firmware_common
)
