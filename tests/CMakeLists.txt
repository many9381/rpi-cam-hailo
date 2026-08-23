find_package(GTest REQUIRED)
find_package(jsoncpp CONFIG REQUIRED)
pkg_check_modules(GSTREAMER_CHECK REQUIRED IMPORTED_TARGET gstreamer-check-1.0)

add_executable(camera_firmware_integrity_tool_tests
    integration/IntegrityToolTest.cpp
)

add_dependencies(camera_firmware_integrity_tool_tests
    camera-firmware-integrity
)

target_compile_definitions(camera_firmware_integrity_tool_tests
    PRIVATE
        CF_INTEGRITY_TOOL="$<TARGET_FILE:camera-firmware-integrity>"
)

target_include_directories(camera_firmware_integrity_tool_tests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(camera_firmware_integrity_tool_tests
    PRIVATE
        camera_firmware_integrity
        GTest::gtest_main
        OpenSSL::Crypto
)

gtest_discover_tests(camera_firmware_integrity_tool_tests
    PROPERTIES
        TIMEOUT 20
)

add_executable(camera_firmware_integrity_tests
    unit/integrity/SafeFileDigestTest.cpp
    unit/integrity/IntegrityManifestTest.cpp
    unit/integrity/IntegritySignerTest.cpp
    unit/integrity/IntegrityVerifierTest.cpp
)

target_link_libraries(camera_firmware_integrity_tests
    PRIVATE
        camera_firmware_integrity_test
        GTest::gtest_main
        OpenSSL::Crypto
)

target_link_options(camera_firmware_integrity_tests
    PRIVATE
        -Wl,--wrap=OPENSSL_cleanse
)

target_include_directories(camera_firmware_integrity_tests
    PRIVATE
        ${PROJECT_SOURCE_DIR}/src/integrity
)

gtest_discover_tests(camera_firmware_integrity_tests
    TEST_FILTER "SafeFileDigestTest.*:IntegrityManifestTest.*:IntegritySignerTest.*:IntegrityVerifierTest.*-SafeFileDigestTest.RejectsFifoWithoutBlocking:IntegrityManifestTest.RejectsPathologicalYamlWithinLimits:IntegrityVerifierTest.RejectsNonRegularArtifactsWithoutBlocking"
)

gtest_discover_tests(camera_firmware_integrity_tests
    TEST_FILTER "SafeFileDigestTest.RejectsFifoWithoutBlocking"
    PROPERTIES
        TIMEOUT 2
)

gtest_discover_tests(camera_firmware_integrity_tests
    TEST_FILTER "IntegrityManifestTest.RejectsPathologicalYamlWithinLimits"
    PROPERTIES
        TIMEOUT 2
)

gtest_discover_tests(camera_firmware_integrity_tests
    TEST_FILTER "IntegrityVerifierTest.RejectsNonRegularArtifactsWithoutBlocking"
    PROPERTIES
        TIMEOUT 2
)

add_executable(camera_firmware_common_tests
    unit/common/ResultTest.cpp
    unit/common/SecureBytesTest.cpp
    unit/common/ThreadTuningTest.cpp
)

target_link_libraries(camera_firmware_common_tests
    PRIVATE
        camera_firmware_common
        GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(camera_firmware_common_tests)

add_executable(camera_firmware_crypto_tests
    unit/crypto/CryptoProviderTest.cpp
)

target_link_libraries(camera_firmware_crypto_tests
    PRIVATE
        camera_firmware_crypto
        GTest::gtest_main
)

gtest_discover_tests(camera_firmware_crypto_tests)

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

add_executable(camera_firmware_settings_tests
    unit/settings/RuntimeSettingsTest.cpp
)

target_link_libraries(camera_firmware_settings_tests
    PRIVATE
        camera_firmware_settings
        GTest::gtest_main
)

gtest_discover_tests(camera_firmware_settings_tests)

add_executable(camera_firmware_runtime_settings_store_tests
    unit/settings/RuntimeSettingsStoreTest.cpp
)

target_link_libraries(camera_firmware_runtime_settings_store_tests
    PRIVATE
        camera_firmware_settings
        GTest::gtest_main
)

target_include_directories(camera_firmware_runtime_settings_store_tests
    PRIVATE
        ${PROJECT_SOURCE_DIR}/src/settings
)

target_link_options(camera_firmware_runtime_settings_store_tests
    PRIVATE
        -Wl,--wrap=fstat
        -Wl,--wrap=camera_firmware_settings_write
        -Wl,--wrap=camera_firmware_settings_fdatasync
        -Wl,--wrap=camera_firmware_settings_renameat
        -Wl,--wrap=camera_firmware_settings_unlinkat
        -Wl,--wrap=camera_firmware_settings_fsync
)

gtest_discover_tests(camera_firmware_runtime_settings_store_tests)

add_executable(camera_firmware_security_production_self_test_link_test
    unit/security/SecuritySelfTestProductionLinkTest.cpp
)

target_link_libraries(camera_firmware_security_production_self_test_link_test
    PRIVATE
        camera_firmware_security
        GTest::gtest_main
)

gtest_discover_tests(camera_firmware_security_production_self_test_link_test)

add_executable(camera_firmware_security_tests
    unit/security/AuditLogServiceTest.cpp
    unit/security/AuthServiceTest.cpp
    unit/security/BootstrapServiceTest.cpp
    unit/security/DeviceTlsManagerTest.cpp
    unit/security/PasswordHasherTest.cpp
    unit/security/PasswordPolicyTest.cpp
    unit/security/SecuritySelfTestTest.cpp
    unit/security/SystemProtectionServiceTest.cpp
    unit/security/SecurityStoreTest.cpp
    unit/security/UserManagementServiceTest.cpp
)

target_link_libraries(camera_firmware_security_tests
    PRIVATE
        camera_firmware_security_self_test
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
        -Wl,--wrap=sqlite3_prepare_v2
        -Wl,--wrap=OPENSSL_cleanse
)

target_compile_definitions(camera_firmware_security_tests
    PRIVATE
        CAMERA_FIRMWARE_SECURITY_SELF_TESTING
        CF_SOURCE_DIR="${PROJECT_SOURCE_DIR}"
)

gtest_discover_tests(camera_firmware_security_tests)

add_executable(camera_firmware_media_tests
    unit/media/CameraPipelineConfigTest.cpp
    unit/media/CameraTimingTest.cpp
    unit/media/EncodeMailboxTest.cpp
    unit/media/EncodedRingTest.cpp
    unit/media/FrameLeaseTest.cpp
    unit/media/FragmentRingTest.cpp
    unit/media/IsoBmffAssemblerTest.cpp
    unit/media/JpegEncoderTest.cpp
    unit/media/LoresGeometryTest.cpp
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
    unit/ai/AlignedBufferPoolTest.cpp
    unit/ai/ModelInputBufferPoolTest.cpp
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

add_executable(camera_firmware_managed_runtime_tests
    unit/runtime/ManagedFirmwareRuntimeTest.cpp
)

target_link_libraries(camera_firmware_managed_runtime_tests
    PRIVATE
        camera_firmware_runtime
        GTest::gtest_main
)

gtest_discover_tests(
    camera_firmware_managed_runtime_tests
    TEST_PREFIX camera_firmware_managed_runtime_tests.
)

add_executable(camera_firmware_runtime_settings_service_tests
    unit/settings/RuntimeSettingsServiceTest.cpp
)

target_compile_definitions(camera_firmware_runtime_settings_service_tests
    PRIVATE
        CF_TEST_BINARY_DIR="${PROJECT_BINARY_DIR}/tests"
)

target_link_libraries(camera_firmware_runtime_settings_service_tests
    PRIVATE
        camera_firmware_runtime
        camera_firmware_settings
        GTest::gtest_main
)

target_link_options(camera_firmware_runtime_settings_service_tests
    PRIVATE
        -Wl,--wrap=camera_firmware_settings_renameat
        -Wl,--wrap=camera_firmware_settings_fsync
        -Wl,--wrap=_ZNK15camera_firmware7runtime22ManagedFirmwareRuntime5StateEv
)

gtest_discover_tests(
    camera_firmware_runtime_settings_service_tests
    TEST_PREFIX camera_firmware_runtime_settings_service_tests.
    PROPERTIES
        TIMEOUT 10
)

add_executable(camera_firmware_runtime_settings_http_tests
    unit/service/RuntimeSettingsHttpTest.cpp
)

target_link_libraries(camera_firmware_runtime_settings_http_tests
    PRIVATE
        camera_firmware_service
        GTest::gtest_main
)

gtest_discover_tests(
    camera_firmware_runtime_settings_http_tests
    TEST_PREFIX camera_firmware_runtime_settings_http_tests.
    PROPERTIES
        TIMEOUT 10
)

add_executable(camera_firmware_boot_tests
    unit/boot/FirmwareBootCoordinatorTest.cpp
)

target_link_libraries(camera_firmware_boot_tests
    PRIVATE
        camera_firmware_boot
        GTest::gtest_main
)

gtest_discover_tests(
    camera_firmware_boot_tests
    PROPERTIES
        TIMEOUT 5
)

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

add_executable(camera_firmware_system_protection_hardware_smoke
    integration/SystemProtectionHardwareSmokeTest.cpp
)

target_link_libraries(camera_firmware_system_protection_hardware_smoke
    PRIVATE
        camera_firmware_runtime
        camera_firmware_security
        GTest::gtest_main
)

gtest_discover_tests(camera_firmware_system_protection_hardware_smoke
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    PROPERTIES
        TIMEOUT 90
        RESOURCE_LOCK camera_firmware_hardware
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

add_executable(camera_firmware_async_stream_backpressure_tests
    integration/AsyncStreamBackpressureTest.cpp
)

target_link_libraries(camera_firmware_async_stream_backpressure_tests
    PRIVATE
        Drogon::Drogon
        GTest::gtest_main
        OpenSSL::SSL
        OpenSSL::Crypto
)

gtest_discover_tests(camera_firmware_async_stream_backpressure_tests
    PROPERTIES
        TIMEOUT 30
        RESOURCE_LOCK camera_firmware_loopback_listener
)

add_executable(camera_firmware_service_tests
    unit/service/AuditLogHttpTest.cpp
    unit/service/SecurityRequestGateTest.cpp
    unit/service/SessionStreamRegistryTest.cpp
    unit/service/ServiceResponseTest.cpp
    unit/service/ServiceStartupTest.cpp
    unit/service/SystemProtectionHttpTest.cpp
    unit/service/UserManagementHttpTest.cpp
)

target_link_libraries(camera_firmware_service_tests
    PRIVATE
        camera_firmware_service_testing
        GTest::gtest_main
)

gtest_discover_tests(camera_firmware_service_tests)

add_executable(camera_firmware_live_mp4_byte_stream_tests
    unit/service/LiveMp4ByteStreamTest.cpp
)

target_include_directories(camera_firmware_live_mp4_byte_stream_tests
    PRIVATE
        ${PROJECT_SOURCE_DIR}/apps/camera-firmware
)

target_link_libraries(camera_firmware_live_mp4_byte_stream_tests
    PRIVATE
        camera_firmware_media
        GTest::gtest_main
)

gtest_discover_tests(
    camera_firmware_live_mp4_byte_stream_tests
    PROPERTIES
        TIMEOUT 15
)

add_test(
    NAME ServiceProductionSurfaceTest.NoTestHooks
    COMMAND ${CMAKE_COMMAND}
        -DSERVICE_LIBRARY=$<TARGET_FILE:camera_firmware_service>
        -DSERVICE_REGISTRY_HEADER=${PROJECT_SOURCE_DIR}/include/camera_firmware/service/SessionStreamRegistry.hpp
        -DNM_EXECUTABLE=${CMAKE_NM}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/ServiceProductionSurfaceTest.cmake
)

add_executable(camera_firmware_https_auth_integration
    integration/HttpsAuthIntegrationTest.cpp
    integration/SystemProtectionIntegrationTest.cpp
)

add_dependencies(camera_firmware_https_auth_integration
    camera-firmware-integration
    camera_firmware_web
)

target_compile_definitions(camera_firmware_https_auth_integration
    PRIVATE
        CF_CAMERA_FIRMWARE_BIN="$<TARGET_FILE:camera-firmware-integration>"
        CF_SOURCE_DIR="${PROJECT_SOURCE_DIR}"
)

target_include_directories(camera_firmware_https_auth_integration
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(camera_firmware_https_auth_integration
    PRIVATE
        camera_firmware_boot
        camera_firmware_integrity_signer
        camera_firmware_service_testing
        GTest::gtest_main
        OpenSSL::SSL
)

# These integration tests each boot a real drogon server and make timing
# assertions; the loopback lock already serializes them against each other,
# and RUN_SERIAL additionally keeps saturated unit suites from stealing the
# cores out from under those timing windows (observed flakes otherwise).
gtest_discover_tests(camera_firmware_https_auth_integration
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    TEST_FILTER "HttpsAuthIntegrationTest.*"
    TEST_SUFFIX .ServiceSecurityIntegrationTest
    PROPERTIES
        TIMEOUT 90
        RESOURCE_LOCK camera_firmware_loopback_listener
        RUN_SERIAL TRUE
)

gtest_discover_tests(camera_firmware_https_auth_integration
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    TEST_FILTER "-HttpsAuthIntegrationTest.*"
    PROPERTIES
        TIMEOUT 90
        RESOURCE_LOCK camera_firmware_loopback_listener
        RUN_SERIAL TRUE
)

add_executable(camera_firmware_user_management_process_integration
    integration/UserManagementProcessIntegrationTest.cpp
)

add_dependencies(camera_firmware_user_management_process_integration
    camera-firmware
    camera_firmware_web
)

target_compile_definitions(camera_firmware_user_management_process_integration
    PRIVATE
        CF_CAMERA_FIRMWARE_BIN="$<TARGET_FILE:camera-firmware>"
        CF_SOURCE_DIR="${PROJECT_SOURCE_DIR}"
)

target_link_libraries(camera_firmware_user_management_process_integration
    PRIVATE
        camera_firmware_security
        GTest::gtest_main
        JsonCpp::JsonCpp
        OpenSSL::SSL
        SQLite::SQLite3
)

gtest_discover_tests(camera_firmware_user_management_process_integration
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    PROPERTIES
        TIMEOUT 90
        RESOURCE_LOCK camera_firmware_loopback_listener
)

if(CAMERA_FIRMWARE_DROGON_SOURCE_DIR AND
        CAMERA_FIRMWARE_TRANTOR_SOURCE_DIR)
    find_program(CF_TEST_GIT_EXECUTABLE NAMES git REQUIRED)
    add_test(
        NAME DrogonSourceIdentityConfigureTest
        COMMAND ${CMAKE_COMMAND}
            -DCF_PROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR}
            -DCF_DROGON_SOURCE_DIR=${CAMERA_FIRMWARE_DROGON_SOURCE_DIR}
            -DCF_TRANTOR_SOURCE_DIR=${CAMERA_FIRMWARE_TRANTOR_SOURCE_DIR}
            -DCF_GIT_EXECUTABLE=${CF_TEST_GIT_EXECUTABLE}
            -DCF_TEST_ROOT=${PROJECT_BINARY_DIR}/drogon-source-identity-test
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/DrogonSourceIdentityTest.cmake
    )
    set_tests_properties(DrogonSourceIdentityConfigureTest
        PROPERTIES
            TIMEOUT 120
    )

    add_test(
        NAME integrity_public_key
        COMMAND ${CMAKE_COMMAND}
            -DCF_PROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR}
            -DCF_DROGON_SOURCE_DIR=${CAMERA_FIRMWARE_DROGON_SOURCE_DIR}
            -DCF_TRANTOR_SOURCE_DIR=${CAMERA_FIRMWARE_TRANTOR_SOURCE_DIR}
            -DCF_TEST_ROOT=${PROJECT_BINARY_DIR}/integrity-public-key-test
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/IntegrityPublicKeyTest.cmake
    )
    set_tests_properties(integrity_public_key
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
