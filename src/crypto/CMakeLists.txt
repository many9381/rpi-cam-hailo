add_library(camera_firmware_crypto STATIC
    OpenSslCryptoProvider.cpp
)

target_include_directories(camera_firmware_crypto
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(camera_firmware_crypto
    PUBLIC
        camera_firmware_common
    PRIVATE
        OpenSSL::Crypto
)
