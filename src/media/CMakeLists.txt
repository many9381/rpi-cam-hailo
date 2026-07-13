add_library(camera_firmware_media STATIC
    CameraPipeline.cpp
    CameraTiming.cpp
    EncodedRing.cpp
    FrameLease.cpp
    JpegEncoder.cpp
    MjpegFrameHub.cpp
    SnapshotTap.cpp
)

target_include_directories(camera_firmware_media
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(camera_firmware_media
    PUBLIC
        camera_firmware_common
        camera_firmware_config
        JPEG::JPEG
        PkgConfig::LIBCAMERA
        PkgConfig::X264
)
