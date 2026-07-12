cmake_minimum_required(VERSION 3.25)

foreach(CF_REQUIRED IN ITEMS CF_PROJECT_SOURCE_DIR CF_TEST_ROOT)
    if(NOT DEFINED ${CF_REQUIRED} OR "${${CF_REQUIRED}}" STREQUAL "")
        message(FATAL_ERROR "BuildWebTest requires -D${CF_REQUIRED}=<value>")
    endif()
endforeach()

find_program(CF_TEST_SH NAMES sh REQUIRED)
find_program(CF_TEST_CP NAMES cp REQUIRED)
find_program(CF_TEST_TOUCH NAMES touch REQUIRED)

set(CF_SOURCE "${CF_TEST_ROOT}/source")
set(CF_BINARY "${CF_TEST_ROOT}/binary")
set(CF_BUILD_COUNT "${CF_TEST_ROOT}/build-count.txt")
set(CF_FAKE_NPM "${CF_TEST_ROOT}/fake-npm.sh")

file(REMOVE_RECURSE "${CF_TEST_ROOT}")
file(MAKE_DIRECTORY "${CF_SOURCE}/src" "${CF_BINARY}")
file(COPY_FILE "${CF_PROJECT_SOURCE_DIR}/web/BuildWeb.cmake"
               "${CF_SOURCE}/BuildWeb.cmake")
foreach(CF_INPUT IN ITEMS CMakeLists.txt index.html package.json
        package-lock.json tsconfig.json tsconfig.node.json vite.config.ts
        vitest.setup.ts)
    file(WRITE "${CF_SOURCE}/${CF_INPUT}" "fixture:${CF_INPUT}\n")
endforeach()
file(WRITE "${CF_SOURCE}/src/main.ts" "export const fixture = true;\n")

file(WRITE "${CF_FAKE_NPM}" [=[#!/bin/sh
set -eu
if [ "$1" = "ci" ]; then
    exit 0
fi
if [ "$1" != "run" ] || [ "$2" != "build" ]; then
    exit 64
fi
count=0
if [ -f "@CF_BUILD_COUNT@" ]; then
    count=$(cat "@CF_BUILD_COUNT@")
fi
count=$((count + 1))
printf '%s\n' "$count" > "@CF_BUILD_COUNT@"
"@CMAKE_COMMAND@" -E remove_directory "$PWD/dist"
"@CMAKE_COMMAND@" -E make_directory "$PWD/dist"
printf 'app-production\n' > "$PWD/dist/app.js"
printf 'index-production\n' > "$PWD/dist/index.html"
printf 'styles-production\n' > "$PWD/dist/styles.css"
]=])
file(READ "${CF_FAKE_NPM}" CF_FAKE_NPM_CONTENT)
string(REPLACE "@CF_BUILD_COUNT@" "${CF_BUILD_COUNT}"
       CF_FAKE_NPM_CONTENT "${CF_FAKE_NPM_CONTENT}")
string(REPLACE "@CMAKE_COMMAND@" "${CMAKE_COMMAND}"
       CF_FAKE_NPM_CONTENT "${CF_FAKE_NPM_CONTENT}")
file(WRITE "${CF_FAKE_NPM}" "${CF_FAKE_NPM_CONTENT}")
file(CHMOD "${CF_FAKE_NPM}"
     PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
                 WORLD_READ WORLD_EXECUTE)

set(CF_BUILD_ARGS
    "-DCF_WEB_SOURCE_DIR=${CF_SOURCE}"
    "-DCF_WEB_BINARY_DIR=${CF_BINARY}"
    "-DCF_WEB_NODE_EXECUTABLE=${CMAKE_COMMAND}"
    "-DCF_WEB_NODE_VERSION=20.0.0"
    "-DCF_WEB_NPM_EXECUTABLE=${CF_FAKE_NPM}"
    "-DCF_WEB_NPM_VERSION=10.0.0"
    -P "${CF_SOURCE}/BuildWeb.cmake")

function(cf_run_build CF_LABEL)
    execute_process(
        COMMAND "${CMAKE_COMMAND}" ${CF_BUILD_ARGS}
        RESULT_VARIABLE CF_RESULT
        OUTPUT_VARIABLE CF_STDOUT
        ERROR_VARIABLE CF_STDERR)
    if(NOT CF_RESULT EQUAL 0)
        message(FATAL_ERROR
            "${CF_LABEL} BuildWeb invocation failed (${CF_RESULT}):\n"
            "${CF_STDOUT}${CF_STDERR}")
    endif()
endfunction()

function(cf_expect_build_count CF_EXPECTED CF_LABEL)
    if(NOT EXISTS "${CF_BUILD_COUNT}")
        message(FATAL_ERROR "${CF_LABEL}: build count file is missing")
    endif()
    file(READ "${CF_BUILD_COUNT}" CF_ACTUAL)
    string(STRIP "${CF_ACTUAL}" CF_ACTUAL)
    if(NOT CF_ACTUAL STREQUAL "${CF_EXPECTED}")
        message(FATAL_ERROR
            "${CF_LABEL}: expected ${CF_EXPECTED} builds, observed ${CF_ACTUAL}")
    endif()
endfunction()

cf_run_build("fresh")
cf_expect_build_count(1 "fresh")
foreach(CF_OUTPUT IN ITEMS app.js index.html styles.css)
    if(NOT EXISTS "${CF_SOURCE}/dist/${CF_OUTPUT}")
        message(FATAL_ERROR "fresh: missing ${CF_OUTPUT}")
    endif()
endforeach()

cf_run_build("warm")
cf_expect_build_count(1 "warm")

file(REMOVE "${CF_SOURCE}/dist/app.js")
cf_run_build("missing output")
cf_expect_build_count(2 "missing output")

file(WRITE "${CF_SOURCE}/dist/extra.txt" "unexpected\n")
cf_run_build("extra output")
cf_expect_build_count(3 "extra output")

set(CF_APP_JS "${CF_SOURCE}/dist/app.js")
set(CF_APP_JS_TIME "${CF_TEST_ROOT}/app.js.mtime")
execute_process(COMMAND "${CF_TEST_CP}" -p "${CF_APP_JS}" "${CF_APP_JS_TIME}"
                COMMAND_ERROR_IS_FATAL ANY)
file(WRITE "${CF_APP_JS}" "bad-production!\n")
execute_process(COMMAND "${CF_TEST_TOUCH}" -r "${CF_APP_JS_TIME}" "${CF_APP_JS}"
                COMMAND_ERROR_IS_FATAL ANY)
cf_run_build("same-name content tamper")
cf_expect_build_count(4 "same-name content tamper")

file(REMOVE "${CF_BINARY}/camera_firmware_web.stamp")
set(CF_CONCURRENT "${CF_TEST_ROOT}/concurrent.sh")
string(JOIN " " CF_BUILD_COMMAND "${CMAKE_COMMAND}" ${CF_BUILD_ARGS})
file(WRITE "${CF_CONCURRENT}"
    "#!/bin/sh\nset -eu\n"
    "${CF_BUILD_COMMAND} > '${CF_TEST_ROOT}/concurrent-1.log' 2>&1 &\n"
    "first=$!\n"
    "${CF_BUILD_COMMAND} > '${CF_TEST_ROOT}/concurrent-2.log' 2>&1 &\n"
    "second=$!\n"
    "wait $first\nwait $second\n")
file(CHMOD "${CF_CONCURRENT}"
     PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
                 WORLD_READ WORLD_EXECUTE)
execute_process(COMMAND "${CF_TEST_SH}" "${CF_CONCURRENT}"
                RESULT_VARIABLE CF_CONCURRENT_RESULT)
if(NOT CF_CONCURRENT_RESULT EQUAL 0)
    message(FATAL_ERROR "concurrent BuildWeb invocation failed")
endif()
cf_expect_build_count(5 "concurrent invocation")

message(STATUS "BuildWeb integrity fixture passed")
