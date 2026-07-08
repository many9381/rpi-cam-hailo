find_package(GTest REQUIRED)

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
)

target_link_libraries(camera_firmware_media_tests
    PRIVATE
        camera_firmware_media
        GTest::gtest_main
)

gtest_discover_tests(camera_firmware_media_tests)
