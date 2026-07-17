add_library(camera_firmware_security STATIC
    AuthService.cpp
    BootstrapService.cpp
    DeviceTlsManager.cpp
    DeviceTlsPlatform.cpp
    PasswordHasher.cpp
    PasswordPolicy.cpp
    SecurityTypes.cpp
    SecurityStore.cpp
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
    PRIVATE
        camera_firmware_rtsp
        OpenSSL::Crypto
        PkgConfig::GIO
        SQLite::SQLite3
)
