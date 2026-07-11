if(NOT CF_PROJECT_SOURCE_DIR OR NOT CF_DROGON_SOURCE_DIR OR
        NOT CF_GIT_EXECUTABLE OR NOT CF_TEST_ROOT)
    message(FATAL_ERROR "Drogon source identity test arguments are required")
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

function(cf_configure source_dir build_dir result_name output_name)
    execute_process(
        COMMAND "${CMAKE_COMMAND}"
                -S "${CF_PROJECT_SOURCE_DIR}"
                -B "${build_dir}"
                -DBUILD_TESTING=OFF
                -DCAMERA_FIRMWARE_DROGON_SOURCE_DIR=${source_dir}
        RESULT_VARIABLE configure_result
        OUTPUT_VARIABLE configure_stdout
        ERROR_VARIABLE configure_stderr
    )
    set(${result_name} "${configure_result}" PARENT_SCOPE)
    set(${output_name} "${configure_stdout}${configure_stderr}" PARENT_SCOPE)
endfunction()

file(REMOVE_RECURSE "${CF_TEST_ROOT}")
file(MAKE_DIRECTORY "${CF_TEST_ROOT}")

set(source_mutation_source "${CF_TEST_ROOT}/source-mutation-src")
set(source_mutation_build "${CF_TEST_ROOT}/source-mutation-build")
cf_clone_drogon("${source_mutation_source}")
cf_configure("${source_mutation_source}" "${source_mutation_build}"
             initial_result initial_output)
if(NOT initial_result EQUAL 0)
    message(FATAL_ERROR "Initial source configure failed: ${initial_output}")
endif()
file(APPEND "${source_mutation_source}/lib/src/HttpUtils.cc"
     "\n// camera-firmware source identity mutation\n")
cf_configure("${source_mutation_source}" "${source_mutation_build}"
             mutation_result mutation_output)
if(mutation_result EQUAL 0)
    message(FATAL_ERROR
        "Reconfigure accepted a mutation in untouched Drogon source")
endif()
if(NOT mutation_output MATCHES "tracked files are modified")
    message(FATAL_ERROR
        "Source mutation failed without the required identity diagnostic: ${mutation_output}")
endif()

set(stale_copy_source "${CF_TEST_ROOT}/stale-copy-src")
set(stale_copy_build "${CF_TEST_ROOT}/stale-copy-build")
cf_clone_drogon("${stale_copy_source}")
cf_configure("${stale_copy_source}" "${stale_copy_build}"
             stale_initial_result stale_initial_output)
if(NOT stale_initial_result EQUAL 0)
    message(FATAL_ERROR
        "Initial stale-copy configure failed: ${stale_initial_output}")
endif()
file(APPEND
     "${stale_copy_build}/_deps/camera-firmware-drogon-1.9.0-src/lib/src/HttpUtils.cc"
     "\n// camera-firmware stale copy mutation\n")
cf_configure("${stale_copy_source}" "${stale_copy_build}"
             stale_result stale_output)
if(stale_result EQUAL 0)
    message(FATAL_ERROR "Reconfigure silently reused a mutated Drogon copy")
endif()
if(NOT stale_output MATCHES "copied patched Drogon 1.9.0 tree was modified")
    message(FATAL_ERROR
        "Stale copy failed without the required diagnostic: ${stale_output}")
endif()
