find_package(jsoncpp CONFIG REQUIRED)

add_library(camera_firmware_settings STATIC
    RuntimeSettings.cpp
    RuntimeSettingsDocumentCodec.cpp
    RuntimeSettingsService.cpp
    RuntimeSettingsStore.cpp
    RuntimeSettingsStorePlatform.cpp
)

target_include_directories(camera_firmware_settings
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(camera_firmware_settings
    PUBLIC
        camera_firmware_config
    PRIVATE
        camera_firmware_runtime
        JsonCpp::JsonCpp
)
