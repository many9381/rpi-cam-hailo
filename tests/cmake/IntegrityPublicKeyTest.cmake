cmake_minimum_required(VERSION 3.25)

if(NOT CF_PROJECT_SOURCE_DIR OR NOT CF_DROGON_SOURCE_DIR OR
        NOT CF_TRANTOR_SOURCE_DIR OR NOT CF_TEST_ROOT)
    message(FATAL_ERROR "Integrity public key test arguments are required")
endif()

file(REMOVE_RECURSE "${CF_TEST_ROOT}")
file(MAKE_DIRECTORY "${CF_TEST_ROOT}")

set(malformed_key "${CF_TEST_ROOT}/malformed-public-key.pem")
file(WRITE "${malformed_key}"
    "-----BEGIN PUBLIC KEY-----\nnot-a-public-key\n-----END PUBLIC KEY-----\n")

find_program(CF_TEST_OPENSSL_EXECUTABLE NAMES openssl REQUIRED)
set(non_development_private_key "${CF_TEST_ROOT}/non-development-private-key.pem")
set(non_development_public_key "${CF_TEST_ROOT}/non-development-public-key.pem")
execute_process(
    COMMAND "${CF_TEST_OPENSSL_EXECUTABLE}" genpkey -algorithm ED25519
            -out "${non_development_private_key}"
    RESULT_VARIABLE generate_key_result
    ERROR_VARIABLE generate_key_error)
if(NOT generate_key_result EQUAL 0)
    message(FATAL_ERROR "Failed to generate test Ed25519 key: ${generate_key_error}")
endif()
execute_process(
    COMMAND "${CF_TEST_OPENSSL_EXECUTABLE}" pkey -in "${non_development_private_key}"
            -pubout -out "${non_development_public_key}"
    RESULT_VARIABLE export_key_result
    ERROR_VARIABLE export_key_error)
if(NOT export_key_result EQUAL 0)
    message(FATAL_ERROR "Failed to export test Ed25519 public key: ${export_key_error}")
endif()

set(default_key_build "${CF_TEST_ROOT}/default-key-build")
foreach(configure_label IN ITEMS initial cached)
    execute_process(
        COMMAND "${CMAKE_COMMAND}"
                -S "${CF_PROJECT_SOURCE_DIR}"
                -B "${default_key_build}"
                -DBUILD_TESTING=OFF
                -DCAMERA_FIRMWARE_DROGON_SOURCE_DIR=${CF_DROGON_SOURCE_DIR}
                -DCAMERA_FIRMWARE_TRANTOR_SOURCE_DIR=${CF_TRANTOR_SOURCE_DIR}
        RESULT_VARIABLE configure_result
        OUTPUT_VARIABLE configure_stdout
        ERROR_VARIABLE configure_stderr)

    if(NOT configure_result EQUAL 0)
        message(FATAL_ERROR
            "${configure_label} configure with the bundled development key failed: "
            "${configure_stdout}${configure_stderr}")
    endif()

    set(configure_output "${configure_stdout}${configure_stderr}")
    if(NOT configure_output MATCHES "Using the development integrity public key")
        message(FATAL_ERROR
            "${configure_label} configure did not warn about the bundled development key: "
            "${configure_output}")
    endif()
endforeach()

execute_process(
    COMMAND "${CMAKE_COMMAND}"
            -S "${CF_PROJECT_SOURCE_DIR}"
            -B "${CF_TEST_ROOT}/non-development-key-build"
            -DBUILD_TESTING=OFF
            -DCAMERA_FIRMWARE_DROGON_SOURCE_DIR=${CF_DROGON_SOURCE_DIR}
            -DCAMERA_FIRMWARE_TRANTOR_SOURCE_DIR=${CF_TRANTOR_SOURCE_DIR}
            -DCF_INTEGRITY_PUBLIC_KEY_FILE=${non_development_public_key}
    RESULT_VARIABLE configure_result
    OUTPUT_VARIABLE configure_stdout
    ERROR_VARIABLE configure_stderr)

if(NOT configure_result EQUAL 0)
    message(FATAL_ERROR
        "Configure with an explicit non-development Ed25519 public key failed: "
        "${configure_stdout}${configure_stderr}")
endif()

set(configure_output "${configure_stdout}${configure_stderr}")
if(configure_output MATCHES "Using the development integrity public key")
    message(FATAL_ERROR
        "Configure with an explicit non-development Ed25519 public key warned: "
        "${configure_output}")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}"
            -S "${CF_PROJECT_SOURCE_DIR}"
            -B "${CF_TEST_ROOT}/malformed-key-build"
            -DBUILD_TESTING=OFF
            -DCAMERA_FIRMWARE_DROGON_SOURCE_DIR=${CF_DROGON_SOURCE_DIR}
            -DCAMERA_FIRMWARE_TRANTOR_SOURCE_DIR=${CF_TRANTOR_SOURCE_DIR}
            -DCF_INTEGRITY_PUBLIC_KEY_FILE=${malformed_key}
    RESULT_VARIABLE configure_result
    OUTPUT_VARIABLE configure_stdout
    ERROR_VARIABLE configure_stderr)

if(configure_result EQUAL 0)
    message(FATAL_ERROR
        "Configure accepted a malformed CF_INTEGRITY_PUBLIC_KEY_FILE")
endif()

set(configure_output "${configure_stdout}${configure_stderr}")
if(NOT configure_output MATCHES
        "CF_INTEGRITY_PUBLIC_KEY_FILE is not a valid public key")
    message(FATAL_ERROR
        "Malformed public key failed without the expected diagnostic: "
        "${configure_output}")
endif()
