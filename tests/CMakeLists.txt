find_package(GTest REQUIRED)
pkg_check_modules(GSTREAMER_CHECK REQUIRED IMPORTED_TARGET gstreamer-check-1.0)

add_executable(camera_firmware_common_tests
    unit/common/ResultTest.cpp
    unit/common/SecureBytesTest.cpp
)

target_link_libraries(camera_firmware_common_tests
    PRIVATE
        camera_firmware_common
        GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(camera_firmware_common_tests)

add_executable(camera_firmware_config_tests
    unit/config/AppConfigTest.cpp
)

target_link_libraries(camera_firmware_config_tests
    PRIVATE
        camera_firmware_config
        camera_firmware_common
        GTest::gtest_main
)

gtest_discover_tests(camera_firmware_config_tests
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
)

add_executable(camera_firmware_media_tests
    unit/media/EncodedRingTest.cpp
    unit/media/FrameLeaseTest.cpp
    unit/media/SnapshotTapTest.cpp
)

target_link_libraries(camera_firmware_media_tests
    PRIVATE
        camera_firmware_media
        GTest::gtest_main
)

gtest_discover_tests(camera_firmware_media_tests)

add_executable(camera_firmware_rtsp_tests
    unit/rtsp/SrtpSessionKeyTest.cpp
)

target_link_libraries(camera_firmware_rtsp_tests
    PRIVATE
        camera_firmware_rtsp
        GTest::gtest_main
)

gtest_discover_tests(camera_firmware_rtsp_tests)

add_executable(camera_firmware_ai_tests
    unit/ai/DetectionBusTest.cpp
    unit/ai/AiFrameTapTest.cpp
    unit/ai/AiRuntimeTest.cpp
)

target_link_libraries(camera_firmware_ai_tests
    PRIVATE
        camera_firmware_ai
        camera_firmware_media
        GTest::gtest_main
)

gtest_discover_tests(camera_firmware_ai_tests)

add_executable(camera_firmware_service_tests
    unit/service/ServiceResponseTest.cpp
    unit/service/ServiceStartupTest.cpp
)

target_link_libraries(camera_firmware_service_tests
    PRIVATE
        camera_firmware_service
        GTest::gtest_main
)

gtest_discover_tests(camera_firmware_service_tests)

add_executable(gst_secure_srtp_tests
    unit/rtsp/CfSecureSrtpEncTest.cpp
)

target_link_libraries(gst_secure_srtp_tests
    PRIVATE
        PkgConfig::GSTREAMER
        PkgConfig::GSTREAMER_CHECK
        GTest::gtest_main
)

gtest_discover_tests(gst_secure_srtp_tests
    PROPERTIES
        ENVIRONMENT "GST_PLUGIN_PATH=${PROJECT_BINARY_DIR}/plugins/gst-secure-srtp"
)

add_executable(camera_firmware_secure_rtsp_config_smoke
    integration/SecureRtspConfigSmokeTest.cpp
)

target_link_libraries(camera_firmware_secure_rtsp_config_smoke
    PRIVATE
        camera_firmware_config
        camera_firmware_rtsp
        GTest::gtest_main
)

gtest_discover_tests(camera_firmware_secure_rtsp_config_smoke
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    PROPERTIES
        ENVIRONMENT "GST_PLUGIN_PATH=${PROJECT_BINARY_DIR}/plugins/gst-secure-srtp"
)
