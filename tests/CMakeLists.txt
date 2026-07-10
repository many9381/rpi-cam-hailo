find_package(GTest REQUIRED)
find_program(NODE_EXECUTABLE node)
set(CF_NODE_TESTS_ENABLED OFF)
set(CF_NODE_MIN_VERSION 18.0.0)
if(NODE_EXECUTABLE)
    execute_process(
        COMMAND ${NODE_EXECUTABLE} --version
        OUTPUT_VARIABLE CF_NODE_VERSION_OUTPUT
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    string(REGEX REPLACE "^v" "" CF_NODE_VERSION "${CF_NODE_VERSION_OUTPUT}")
    if(CF_NODE_VERSION MATCHES "^[0-9]+(\\.[0-9]+)*$" AND
            CF_NODE_VERSION VERSION_GREATER_EQUAL "${CF_NODE_MIN_VERSION}")
        set(CF_NODE_TESTS_ENABLED ON)
    else()
        message(STATUS
            "Skipping WebAppTest: Node.js ${CF_NODE_VERSION_OUTPUT} is older than ${CF_NODE_MIN_VERSION}"
        )
    endif()
endif()
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
    unit/security/SecurityStoreTest.cpp
)

target_link_libraries(camera_firmware_security_tests
    PRIVATE
        camera_firmware_security
        camera_firmware_common
        GTest::gtest_main
)

target_link_options(camera_firmware_security_tests
    PRIVATE
        -Wl,--wrap=lstat
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

if(CF_NODE_TESTS_ENABLED)
    add_test(
        NAME WebAppTest
        COMMAND ${NODE_EXECUTABLE} --test tests/web/app_test.js
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    )
endif()
