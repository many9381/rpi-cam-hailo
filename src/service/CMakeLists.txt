add_library(camera_firmware_service STATIC
    ServiceApp.cpp
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
        camera_firmware_config
        Drogon::Drogon
)
