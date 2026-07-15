if(NOT CF_PROJECT_SOURCE_DIR OR NOT CF_DROGON_SOURCE_DIR OR
        NOT CF_TRANTOR_SOURCE_DIR OR NOT CF_GIT_EXECUTABLE OR
        NOT CF_TEST_ROOT)
    message(FATAL_ERROR "Drogon and Trantor source identity test arguments are required")
endif()

function(cf_clone_drogon destination)
    execute_process(
        COMMAND "${CF_GIT_EXECUTABLE}" clone --quiet --no-hardlinks
                "${CF_DROGON_SOURCE_DIR}" "${destination}"
        RESULT_VARIABLE clone_result
        ERROR_VARIABLE clone_error
    )
    if(NOT clone_result EQUAL 0)
        message(FATAL_ERROR "Failed to clone Drogon test source: ${clone_error}")
    endif()
endfunction()

function(cf_clone_trantor destination)
    execute_process(
        COMMAND "${CF_GIT_EXECUTABLE}" clone --quiet --no-hardlinks
                "${CF_TRANTOR_SOURCE_DIR}" "${destination}"
        RESULT_VARIABLE clone_result
        ERROR_VARIABLE clone_error
    )
    if(NOT clone_result EQUAL 0)
        message(FATAL_ERROR "Failed to clone Trantor test source: ${clone_error}")
    endif()
endfunction()

function(cf_configure drogon_source trantor_source build_dir result_name output_name)
    execute_process(
        COMMAND "${CMAKE_COMMAND}"
                -S "${CF_PROJECT_SOURCE_DIR}"
                -B "${build_dir}"
                -DBUILD_TESTING=OFF
                -DCAMERA_FIRMWARE_DROGON_SOURCE_DIR=${drogon_source}
                -DCAMERA_FIRMWARE_TRANTOR_SOURCE_DIR=${trantor_source}
        RESULT_VARIABLE configure_result
        OUTPUT_VARIABLE configure_stdout
        ERROR_VARIABLE configure_stderr
    )
    set(${result_name} "${configure_result}" PARENT_SCOPE)
    set(${output_name} "${configure_stdout}${configure_stderr}" PARENT_SCOPE)
endfunction()

file(REMOVE_RECURSE "${CF_TEST_ROOT}")
file(MAKE_DIRECTORY "${CF_TEST_ROOT}")

set(installed_fallback_build "${CF_TEST_ROOT}/installed-fallback-build")
execute_process(
    COMMAND "${CMAKE_COMMAND}"
            -S "${CF_PROJECT_SOURCE_DIR}"
            -B "${installed_fallback_build}"
            -DBUILD_TESTING=OFF
    RESULT_VARIABLE installed_fallback_result
    OUTPUT_VARIABLE installed_fallback_stdout
    ERROR_VARIABLE installed_fallback_stderr
)
set(installed_fallback_output
    "${installed_fallback_stdout}${installed_fallback_stderr}")
if(installed_fallback_result EQUAL 0)
    message(FATAL_ERROR
        "Configure accepted unverifiable installed Drogon and Trantor packages")
endif()
if(NOT installed_fallback_output MATCHES
        "exact Drogon and Trantor source directories are required")
    message(FATAL_ERROR
        "Installed fallback failed without the required provenance diagnostic: ${installed_fallback_output}")
endif()

set(source_mutation_source "${CF_TEST_ROOT}/source-mutation-src")
set(source_mutation_trantor "${CF_TEST_ROOT}/source-mutation-trantor")
set(source_mutation_build "${CF_TEST_ROOT}/source-mutation-build")
cf_clone_drogon("${source_mutation_source}")
cf_clone_trantor("${source_mutation_trantor}")
cf_configure("${source_mutation_source}" "${source_mutation_trantor}"
             "${source_mutation_build}"
             initial_result initial_output)
if(NOT initial_result EQUAL 0)
    message(FATAL_ERROR "Initial source configure failed: ${initial_output}")
endif()
file(APPEND "${source_mutation_source}/lib/src/HttpUtils.cc"
     "\n// camera-firmware source identity mutation\n")
cf_configure("${source_mutation_source}" "${source_mutation_trantor}"
             "${source_mutation_build}"
             mutation_result mutation_output)
if(mutation_result EQUAL 0)
    message(FATAL_ERROR
        "Reconfigure accepted a mutation in untouched Drogon source")
endif()
if(NOT mutation_output MATCHES "tracked files are modified")
    message(FATAL_ERROR
        "Source mutation failed without the required identity diagnostic: ${mutation_output}")
endif()

set(trantor_mutation_drogon "${CF_TEST_ROOT}/trantor-mutation-drogon")
set(trantor_mutation_source "${CF_TEST_ROOT}/trantor-mutation-src")
set(trantor_mutation_build "${CF_TEST_ROOT}/trantor-mutation-build")
cf_clone_drogon("${trantor_mutation_drogon}")
cf_clone_trantor("${trantor_mutation_source}")
cf_configure("${trantor_mutation_drogon}" "${trantor_mutation_source}"
             "${trantor_mutation_build}" trantor_initial_result
             trantor_initial_output)
if(NOT trantor_initial_result EQUAL 0)
    message(FATAL_ERROR
        "Initial Trantor source configure failed: ${trantor_initial_output}")
endif()
file(APPEND "${trantor_mutation_source}/trantor/net/AsyncStream.h"
     "\n// camera-firmware Trantor source identity mutation\n")
cf_configure("${trantor_mutation_drogon}" "${trantor_mutation_source}"
             "${trantor_mutation_build}" trantor_mutation_result
             trantor_mutation_output)
if(trantor_mutation_result EQUAL 0)
    message(FATAL_ERROR
        "Reconfigure accepted a mutation in untouched Trantor source")
endif()
if(NOT trantor_mutation_output MATCHES "tracked files are modified")
    message(FATAL_ERROR
        "Trantor source mutation failed without the required identity diagnostic: ${trantor_mutation_output}")
endif()

set(stale_copy_source "${CF_TEST_ROOT}/stale-copy-src")
set(stale_copy_trantor "${CF_TEST_ROOT}/stale-copy-trantor")
set(stale_copy_build "${CF_TEST_ROOT}/stale-copy-build")
cf_clone_drogon("${stale_copy_source}")
cf_clone_trantor("${stale_copy_trantor}")
cf_configure("${stale_copy_source}" "${stale_copy_trantor}"
             "${stale_copy_build}"
             stale_initial_result stale_initial_output)
if(NOT stale_initial_result EQUAL 0)
    message(FATAL_ERROR
        "Initial stale-copy configure failed: ${stale_initial_output}")
endif()
file(APPEND
     "${stale_copy_build}/_deps/camera-firmware-drogon-1.9.0-src/lib/src/HttpUtils.cc"
     "\n// camera-firmware stale copy mutation\n")
cf_configure("${stale_copy_source}" "${stale_copy_trantor}"
             "${stale_copy_build}"
             stale_result stale_output)
if(stale_result EQUAL 0)
    message(FATAL_ERROR "Reconfigure silently reused a mutated Drogon copy")
endif()
if(NOT stale_output MATCHES "copied patched Drogon 1.9.0 tree was modified")
    message(FATAL_ERROR
        "Stale copy failed without the required diagnostic: ${stale_output}")
endif()
