add_library(camera_firmware_media STATIC
    CameraPipeline.cpp
    CameraTiming.cpp
    EncodeMailbox.cpp
    EncodedRing.cpp
    FragmentRing.cpp
    FragmentedMp4Hub.cpp
    FrameLease.cpp
    IsoBmffAssembler.cpp
    JpegEncoder.cpp
    Nv12Downscaler.cpp
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
        PkgConfig::GSTREAMER_APP
        PkgConfig::LIBCAMERA
        PkgConfig::X264
    PRIVATE
        PkgConfig::LIBSWSCALE
        PkgConfig::LIBAVUTIL
)
