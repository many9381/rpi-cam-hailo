pkg_check_modules(GSTREAMER_RTSP REQUIRED IMPORTED_TARGET gstreamer-rtsp-1.0)

add_library(camera_firmware_rtsp STATIC
    GstRtspDigestAuth.cpp
    GstRtspClientLifecycle.cpp
    RtspDigestCredentials.cpp
    RtspDigestCrypto.cpp
    RtspDigestNonce.cpp
    RtspDigestVerifier.cpp
    SecureRtspServer.cpp
    SrtpSessionKey.cpp
)

set_target_properties(camera_firmware_rtsp
    PROPERTIES
        POSITION_INDEPENDENT_CODE ON
)

target_include_directories(camera_firmware_rtsp
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(camera_firmware_rtsp
    PUBLIC
        camera_firmware_common
        camera_firmware_config
        camera_firmware_media
        PkgConfig::GSTREAMER
        PkgConfig::GSTREAMER_APP
        PkgConfig::GSTREAMER_RTSP
        PkgConfig::GSTREAMER_RTSP_SERVER
        PkgConfig::GIO
    PRIVATE
        OpenSSL::Crypto
)
