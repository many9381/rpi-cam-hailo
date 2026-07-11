add_library(camera_firmware_service STATIC
    BoundedWorker.cpp
    SecurityRequestGate.cpp
    ServiceApp.cpp
    ServiceStartup.cpp
)

set_target_properties(camera_firmware_service
    PROPERTIES
        POSITION_INDEPENDENT_CODE ON
)

target_include_directories(camera_firmware_service
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(camera_firmware_service
    PUBLIC
        camera_firmware_ai
        camera_firmware_config
        camera_firmware_security
        Drogon::Drogon
    PRIVATE
        OpenSSL::Crypto
        PkgConfig::GIO
)
