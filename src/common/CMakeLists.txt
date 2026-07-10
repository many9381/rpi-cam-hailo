add_library(camera_firmware_common STATIC
    Logger.cpp
    SecureBytes.cpp
)

set_target_properties(camera_firmware_common
    PROPERTIES
        POSITION_INDEPENDENT_CODE ON
)

target_include_directories(camera_firmware_common
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(camera_firmware_common
    PUBLIC
        OpenSSL::Crypto
)

target_compile_definitions(camera_firmware_common
    PUBLIC
        CAMERA_FIRMWARE_HAS_OPENSSL=1
)
