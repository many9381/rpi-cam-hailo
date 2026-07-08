add_library(camera_firmware_common STATIC
    Logger.cpp
    SecureBytes.cpp
)

target_include_directories(camera_firmware_common
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

if(OpenSSL_FOUND)
    target_link_libraries(camera_firmware_common
        PUBLIC
            OpenSSL::Crypto
    )
    target_compile_definitions(camera_firmware_common
        PUBLIC
            CAMERA_FIRMWARE_HAS_OPENSSL=1
    )
endif()
