add_library(camera_firmware_security STATIC
    AuditLogService.cpp
    AuthService.cpp
    BootstrapService.cpp
    LoginRateLimiter.cpp
    DeviceTlsManager.cpp
    DeviceTlsPlatform.cpp
    PasswordHasher.cpp
    PasswordPolicy.cpp
    SecuritySelfTest.cpp
    SecurityTypes.cpp
    SecurityStore.cpp
    SystemProtectionService.cpp
    UserManagementService.cpp
)

target_include_directories(camera_firmware_security
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(camera_firmware_security
    PUBLIC
        camera_firmware_common
        camera_firmware_config
        camera_firmware_crypto
    PRIVATE
        camera_firmware_integrity
        camera_firmware_rtsp
        OpenSSL::Crypto
        PkgConfig::GIO
        SQLite::SQLite3
)

if(BUILD_TESTING)
    add_library(camera_firmware_security_self_test STATIC
        SecuritySelfTest.cpp
    )

    target_compile_definitions(camera_firmware_security_self_test
        PRIVATE
            CAMERA_FIRMWARE_SECURITY_SELF_TESTING
    )

    target_include_directories(camera_firmware_security_self_test
        PUBLIC
            ${PROJECT_SOURCE_DIR}/include
    )

    target_link_libraries(camera_firmware_security_self_test
        PRIVATE
            camera_firmware_common
            OpenSSL::Crypto
    )
endif()
