set(CF_OSD_FONT_PATH "${PROJECT_SOURCE_DIR}/vendor/fonts/NanumGothicBold.ttf")
configure_file(OsdFontData.S.in "${CMAKE_CURRENT_BINARY_DIR}/OsdFontData.S" @ONLY)
set_source_files_properties("${CMAKE_CURRENT_BINARY_DIR}/OsdFontData.S"
    PROPERTIES OBJECT_DEPENDS "${CF_OSD_FONT_PATH}")

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
    OsdCompositor.cpp
    OsdFontData.cpp
    "${CMAKE_CURRENT_BINARY_DIR}/OsdFontData.S"
    SnapshotTap.cpp
    SubStreamEncoder.cpp
    SubStreamTap.cpp
    TextRasterizer.cpp
)

target_include_directories(camera_firmware_media
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
    PRIVATE
        ${PROJECT_SOURCE_DIR}/vendor/stb
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
