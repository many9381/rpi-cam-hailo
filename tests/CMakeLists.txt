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

add_executable(camera_firmware_security_tests
    unit/security/AuthServiceTest.cpp
    unit/security/BootstrapServiceTest.cpp
    unit/security/DeviceTlsManagerTest.cpp
    unit/security/PasswordHasherTest.cpp
    unit/security/PasswordPolicyTest.cpp
    unit/security/SecurityStoreTest.cpp
)

target_link_libraries(camera_firmware_security_tests
    PRIVATE
        camera_firmware_security
        camera_firmware_common
        camera_firmware_rtsp
        GTest::gtest_main
)

target_link_options(camera_firmware_security_tests
    PRIVATE
        -Wl,--wrap=lstat
        -Wl,--wrap=fstat
        -Wl,--wrap=close
        -Wl,--wrap=fsync
        -Wl,--wrap=camera_firmware_tls_rename_noreplace
        -Wl,--wrap=sqlite3_open_v2
        -Wl,--wrap=sqlite3_busy_timeout
        -Wl,--wrap=sqlite3_close_v2
        -Wl,--wrap=sqlite3_exec
)

target_compile_definitions(camera_firmware_security_tests
    PRIVATE
        CF_SOURCE_DIR="${PROJECT_SOURCE_DIR}"
)

gtest_discover_tests(camera_firmware_security_tests)

add_executable(camera_firmware_media_tests
    unit/media/CameraPipelineConfigTest.cpp
    unit/media/CameraTimingTest.cpp
    unit/media/EncodedRingTest.cpp
    unit/media/FrameLeaseTest.cpp
    unit/media/FragmentRingTest.cpp
    unit/media/IsoBmffAssemblerTest.cpp
    unit/media/JpegEncoderTest.cpp
    unit/media/SnapshotTapTest.cpp
)

target_link_libraries(camera_firmware_media_tests
    PRIVATE
        camera_firmware_media
        camera_firmware_ai
        GTest::gtest_main
)

target_link_options(camera_firmware_media_tests
    PRIVATE
        -Wl,--wrap=ioctl
)

gtest_discover_tests(camera_firmware_media_tests)

add_executable(camera_firmware_rtsp_tests
    unit/rtsp/GstRtspDigestAuthTest.cpp
    unit/rtsp/GstRtspClientLifecycleTest.cpp
    unit/rtsp/RtspDigestCredentialsTest.cpp
    unit/rtsp/RtspDigestCryptoTest.cpp
    unit/rtsp/RtspDigestNonceTest.cpp
    unit/rtsp/RtspDigestVerifierTest.cpp
    unit/rtsp/SrtpSessionKeyTest.cpp
)

target_include_directories(camera_firmware_rtsp_tests
    PRIVATE
        ${PROJECT_SOURCE_DIR}/src/rtsp
)

target_link_libraries(camera_firmware_rtsp_tests
    PRIVATE
        camera_firmware_rtsp
        GTest::gtest_main
)

gtest_discover_tests(camera_firmware_rtsp_tests
    PROPERTIES
        TIMEOUT 10
)

add_executable(camera_firmware_ai_tests
    unit/ai/DetectionBusTest.cpp
    unit/ai/AiFramePumpTest.cpp
    unit/ai/AiFrameTapTest.cpp
    unit/ai/AiModelProcessorTest.cpp
    unit/ai/Nv12RgbPreprocessorTest.cpp
    unit/ai/AiRuntimeTest.cpp
    unit/ai/DetectionEventStoreTest.cpp
    unit/ai/YoloPostprocessTest.cpp
)

target_link_libraries(camera_firmware_ai_tests
    PRIVATE
        camera_firmware_ai
        camera_firmware_media
        GTest::gtest_main
)
if(CF_TEST_EXPECT_HAILORT)
    target_compile_definitions(camera_firmware_ai_tests
        PRIVATE
            CF_TEST_EXPECT_HAILORT=1
    )
endif()

gtest_discover_tests(camera_firmware_ai_tests)

add_executable(camera_firmware_runtime_tests
    unit/runtime/FirmwareRuntimeTest.cpp
)

target_link_libraries(camera_firmware_runtime_tests
    PRIVATE
        camera_firmware_runtime
        GTest::gtest_main
)

gtest_discover_tests(camera_firmware_runtime_tests)

add_executable(camera_firmware_boot_tests
    unit/boot/FirmwareBootCoordinatorTest.cpp
)

target_link_libraries(camera_firmware_boot_tests
    PRIVATE
        camera_firmware_boot
        GTest::gtest_main
)

gtest_discover_tests(camera_firmware_boot_tests)

add_executable(camera_firmware_ai_hardware_smoke
    integration/AiHardwareSmokeTest.cpp
)

target_link_libraries(camera_firmware_ai_hardware_smoke
    PRIVATE
        camera_firmware_ai
        camera_firmware_config
        GTest::gtest_main
)

gtest_add_tests(TARGET camera_firmware_ai_hardware_smoke
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    TEST_LIST camera_firmware_ai_hardware_smoke_tests
)

set_tests_properties(${camera_firmware_ai_hardware_smoke_tests}
    PROPERTIES
        TIMEOUT 30
)

add_executable(camera_firmware_camera_hardware_smoke
    integration/CameraPipelineHardwareSmokeTest.cpp
)

target_link_libraries(camera_firmware_camera_hardware_smoke
    PRIVATE
        camera_firmware_media
        camera_firmware_ai
        GTest::gtest_main
)

gtest_add_tests(TARGET camera_firmware_camera_hardware_smoke
    TEST_LIST camera_firmware_camera_hardware_smoke_tests
)

set_tests_properties(${camera_firmware_camera_hardware_smoke_tests}
    PROPERTIES
        TIMEOUT 20
)

add_executable(camera_firmware_fragmented_mp4_tests
    integration/FragmentedMp4HubTest.cpp
)

target_link_libraries(camera_firmware_fragmented_mp4_tests
    PRIVATE
        camera_firmware_media
        GTest::gtest_main
)

gtest_discover_tests(camera_firmware_fragmented_mp4_tests
    PROPERTIES
        TIMEOUT 15
)

add_executable(camera_firmware_service_tests
    unit/service/SecurityRequestGateTest.cpp
    unit/service/ServiceResponseTest.cpp
    unit/service/ServiceStartupTest.cpp
)

target_link_libraries(camera_firmware_service_tests
    PRIVATE
        camera_firmware_service
        GTest::gtest_main
)

gtest_discover_tests(camera_firmware_service_tests)

add_executable(camera_firmware_https_auth_integration
    integration/HttpsAuthIntegrationTest.cpp
)

add_dependencies(camera_firmware_https_auth_integration
    camera-firmware
    camera_firmware_web
)

target_compile_definitions(camera_firmware_https_auth_integration
    PRIVATE
        CF_CAMERA_FIRMWARE_BIN="$<TARGET_FILE:camera-firmware>"
        CF_SOURCE_DIR="${PROJECT_SOURCE_DIR}"
)

target_link_libraries(camera_firmware_https_auth_integration
    PRIVATE
        camera_firmware_boot
        camera_firmware_service
        GTest::gtest_main
        OpenSSL::SSL
)

gtest_discover_tests(camera_firmware_https_auth_integration
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    PROPERTIES
        TIMEOUT 90
)

if(CAMERA_FIRMWARE_DROGON_SOURCE_DIR)
    find_program(CF_TEST_GIT_EXECUTABLE NAMES git REQUIRED)
    add_test(
        NAME DrogonSourceIdentityConfigureTest
        COMMAND ${CMAKE_COMMAND}
            -DCF_PROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR}
            -DCF_DROGON_SOURCE_DIR=${CAMERA_FIRMWARE_DROGON_SOURCE_DIR}
            -DCF_GIT_EXECUTABLE=${CF_TEST_GIT_EXECUTABLE}
            -DCF_TEST_ROOT=${PROJECT_BINARY_DIR}/drogon-source-identity-test
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/DrogonSourceIdentityTest.cmake
    )
    set_tests_properties(DrogonSourceIdentityConfigureTest
        PROPERTIES
            TIMEOUT 120
    )
endif()

add_test(
    NAME BuildWebIntegrityTest
    COMMAND ${CMAKE_COMMAND}
        -DCF_PROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR}
        -DCF_TEST_ROOT=${PROJECT_BINARY_DIR}/build-web-integrity-test
        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/BuildWebTest.cmake
)
set_tests_properties(BuildWebIntegrityTest
    PROPERTIES
        TIMEOUT 120
)

add_test(
    NAME WebNodeVersionTest
    COMMAND ${CMAKE_COMMAND}
        -DCF_PROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/NodeVersionTest.cmake
)

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
    integration/RtspDigestAuthIntegrationTest.cpp
    integration/RtspDigestCredentialCliTest.cpp
    integration/SecureRtspConfigSmokeTest.cpp
)

target_compile_definitions(camera_firmware_secure_rtsp_config_smoke
    PRIVATE
        CF_RTSP_DIGEST_CREDENTIAL_TOOL="$<TARGET_FILE:rtsp-digest-credential>"
)

add_dependencies(camera_firmware_secure_rtsp_config_smoke
    rtsp-digest-credential
)

target_link_libraries(camera_firmware_secure_rtsp_config_smoke
    PRIVATE
        camera_firmware_config
        camera_firmware_rtsp
        GTest::gtest_main
        OpenSSL::SSL
        OpenSSL::Crypto
)

gtest_discover_tests(camera_firmware_secure_rtsp_config_smoke
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    PROPERTIES
        ENVIRONMENT "GST_PLUGIN_PATH=${PROJECT_BINARY_DIR}/plugins/gst-secure-srtp"
)
