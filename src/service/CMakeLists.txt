set(CAMERA_FIRMWARE_SERVICE_SOURCES
    AuditLogHttp.cpp
    BoundedWorker.cpp
    RuntimeSettingsHttp.cpp
    SecurityRequestGate.cpp
    SessionStreamRegistry.cpp
    ServiceApp.cpp
    ServiceStartup.cpp
    UserManagementHttp.cpp
)

function(add_camera_firmware_service_library target_name)
    add_library(${target_name} STATIC
        ${CAMERA_FIRMWARE_SERVICE_SOURCES}
    )

    set_target_properties(${target_name}
        PROPERTIES
            POSITION_INDEPENDENT_CODE ON
    )

    target_include_directories(${target_name}
        PUBLIC
            ${PROJECT_SOURCE_DIR}/include
    )

    target_link_libraries(${target_name}
        PUBLIC
            camera_firmware_ai
            camera_firmware_config
            camera_firmware_security
            camera_firmware_settings
            Drogon::Drogon
        PRIVATE
            OpenSSL::Crypto
            PkgConfig::GIO
    )
endfunction()

add_camera_firmware_service_library(camera_firmware_service)

if(BUILD_TESTING)
    add_camera_firmware_service_library(camera_firmware_service_testing)
    target_compile_definitions(camera_firmware_service_testing
        PRIVATE
            CAMERA_FIRMWARE_SERVICE_TESTING=1
    )
endif()
