add_library(camera_firmware_security STATIC
    PasswordHasher.cpp
    PasswordPolicy.cpp
    SecurityStore.cpp
)

target_include_directories(camera_firmware_security
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(camera_firmware_security
    PUBLIC
        camera_firmware_common
    PRIVATE
        OpenSSL::Crypto
        SQLite::SQLite3
)
