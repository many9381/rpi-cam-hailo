set(CAMERA_FIRMWARE_INTEGRITY_SOURCES
    ${CF_INTEGRITY_TRUST_ANCHOR_SOURCE}
    SafeFileDigest.cpp
    IntegrityManifest.cpp
    IntegrityVerifier.cpp
)

function(camera_firmware_configure_integrity_target target)
    target_include_directories(${target}
        PUBLIC
            ${PROJECT_SOURCE_DIR}/include
    )

    target_link_libraries(${target}
        PUBLIC
            camera_firmware_common
            camera_firmware_crypto
            yaml-cpp::yaml-cpp
        PRIVATE
            OpenSSL::Crypto
    )
endfunction()

add_library(camera_firmware_integrity STATIC
    ${CAMERA_FIRMWARE_INTEGRITY_SOURCES}
)
camera_firmware_configure_integrity_target(camera_firmware_integrity)

add_library(camera_firmware_integrity_signer STATIC EXCLUDE_FROM_ALL
    IntegritySigner.cpp
)

target_include_directories(camera_firmware_integrity_signer
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(camera_firmware_integrity_signer
    PUBLIC
        camera_firmware_integrity
    PRIVATE
        OpenSSL::Crypto
)

if(BUILD_TESTING)
    add_library(camera_firmware_integrity_test STATIC EXCLUDE_FROM_ALL
        ${CAMERA_FIRMWARE_INTEGRITY_SOURCES}
        IntegritySigner.cpp
    )
    target_compile_definitions(camera_firmware_integrity_test
        PRIVATE
            CAMERA_FIRMWARE_INTEGRITY_TESTING=1
    )
    camera_firmware_configure_integrity_target(camera_firmware_integrity_test)
endif()
