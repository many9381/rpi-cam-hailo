cmake_minimum_required(VERSION 3.25)

foreach(CF_WEB_REQUIRED_VARIABLE IN ITEMS
        CF_WEB_SOURCE_DIR
        CF_WEB_BINARY_DIR
        CF_WEB_NODE_EXECUTABLE
        CF_WEB_NODE_VERSION
        CF_WEB_NPM_EXECUTABLE
        CF_WEB_NPM_VERSION)
    if(NOT DEFINED ${CF_WEB_REQUIRED_VARIABLE} OR
            "${${CF_WEB_REQUIRED_VARIABLE}}" STREQUAL "")
        message(FATAL_ERROR
            "BuildWeb.cmake requires -D${CF_WEB_REQUIRED_VARIABLE}=<value>"
        )
    endif()
endforeach()

foreach(CF_WEB_TOOL_VARIABLE IN ITEMS
        CF_WEB_NODE_EXECUTABLE
        CF_WEB_NPM_EXECUTABLE)
    if(NOT EXISTS "${${CF_WEB_TOOL_VARIABLE}}")
        message(FATAL_ERROR
            "Configured web tool ${CF_WEB_TOOL_VARIABLE} does not exist: "
            "${${CF_WEB_TOOL_VARIABLE}}"
        )
    endif()
endforeach()

file(REAL_PATH "${CF_WEB_NODE_EXECUTABLE}" CF_WEB_NODE_TOOL_IDENTITY)
file(REAL_PATH "${CF_WEB_NPM_EXECUTABLE}" CF_WEB_NPM_TOOL_IDENTITY)

set(CF_WEB_DIST_DIR "${CF_WEB_SOURCE_DIR}/dist")
set(CF_WEB_STAMP "${CF_WEB_BINARY_DIR}/camera_firmware_web.stamp")
set(CF_WEB_MANIFEST "${CF_WEB_BINARY_DIR}/camera_firmware_web.inputs.sha256")
set(CF_WEB_OUTPUT_MANIFEST
    "${CF_WEB_BINARY_DIR}/camera_firmware_web.outputs.sha256")
set(CF_WEB_EXPECTED_OUTPUTS app.js index.html styles.css)

# The ignored TypeScript-metadata suffix keeps this source-tree lock stable
# while npm replaces node_modules and Vite replaces dist.
set(CF_WEB_LOCK
    "${CF_WEB_SOURCE_DIR}/.camera-firmware-web-lock.tsbuildinfo"
)
message(STATUS "Waiting for camera firmware web source-tree lock")
file(LOCK "${CF_WEB_LOCK}"
    GUARD PROCESS
    TIMEOUT 600
    RESULT_VARIABLE CF_WEB_LOCK_RESULT
)
if(NOT CF_WEB_LOCK_RESULT STREQUAL "0")
    message(FATAL_ERROR
        "Unable to acquire the camera firmware web build lock: "
        "${CF_WEB_LOCK_RESULT}"
    )
endif()
message(STATUS "Acquired camera firmware web source-tree lock")

function(cf_web_get_dist_inventory CF_WEB_RESULT)
    set(CF_WEB_INVENTORY)
    if(IS_DIRECTORY "${CF_WEB_DIST_DIR}")
        file(GLOB CF_WEB_DIST_ENTRIES
            RELATIVE "${CF_WEB_DIST_DIR}"
            LIST_DIRECTORIES true
            "${CF_WEB_DIST_DIR}/*"
            "${CF_WEB_DIST_DIR}/.*"
        )
        list(REMOVE_ITEM CF_WEB_DIST_ENTRIES "." "..")
        list(SORT CF_WEB_DIST_ENTRIES)
        set(CF_WEB_INVENTORY ${CF_WEB_DIST_ENTRIES})
    endif()
    set(${CF_WEB_RESULT} "${CF_WEB_INVENTORY}" PARENT_SCOPE)
endfunction()

function(cf_web_create_output_manifest CF_WEB_MANIFEST_RESULT)
    set(CF_WEB_CURRENT_OUTPUT_MANIFEST
        "camera-firmware-web-output-manifest-v1\n")
    foreach(CF_WEB_OUTPUT IN LISTS CF_WEB_EXPECTED_OUTPUTS)
        set(CF_WEB_OUTPUT_PATH "${CF_WEB_DIST_DIR}/${CF_WEB_OUTPUT}")
        if(NOT EXISTS "${CF_WEB_OUTPUT_PATH}")
            message(FATAL_ERROR
                "Required camera firmware web output is missing: "
                "${CF_WEB_OUTPUT}"
            )
        endif()
        file(SHA256 "${CF_WEB_OUTPUT_PATH}" CF_WEB_OUTPUT_SHA256)
        string(APPEND CF_WEB_CURRENT_OUTPUT_MANIFEST
            "output\t${CF_WEB_OUTPUT}\t${CF_WEB_OUTPUT_SHA256}\n"
        )
    endforeach()
    set(${CF_WEB_MANIFEST_RESULT}
        "${CF_WEB_CURRENT_OUTPUT_MANIFEST}" PARENT_SCOPE)
endfunction()

function(cf_web_create_input_manifest CF_WEB_MANIFEST_RESULT)
    set(CF_WEB_INPUT_RELATIVE_PATHS
        BuildWeb.cmake
        CMakeLists.txt
        index.html
        package.json
        package-lock.json
        tsconfig.json
        tsconfig.node.json
        vite.config.ts
        vitest.setup.ts
    )
    file(GLOB_RECURSE CF_WEB_SOURCE_INPUTS
        RELATIVE "${CF_WEB_SOURCE_DIR}"
        LIST_DIRECTORIES false
        "${CF_WEB_SOURCE_DIR}/src/*"
    )
    list(APPEND CF_WEB_INPUT_RELATIVE_PATHS ${CF_WEB_SOURCE_INPUTS})
    list(REMOVE_DUPLICATES CF_WEB_INPUT_RELATIVE_PATHS)
    list(SORT CF_WEB_INPUT_RELATIVE_PATHS)

    set(CF_WEB_CURRENT_MANIFEST
        "camera-firmware-web-input-manifest-v1\n"
    )
    string(APPEND CF_WEB_CURRENT_MANIFEST
        "node-executable\t${CF_WEB_NODE_TOOL_IDENTITY}\n"
        "node-version\t${CF_WEB_NODE_VERSION}\n"
        "npm-executable\t${CF_WEB_NPM_TOOL_IDENTITY}\n"
        "npm-version\t${CF_WEB_NPM_VERSION}\n"
    )

    foreach(CF_WEB_INPUT_RELATIVE_PATH IN LISTS CF_WEB_INPUT_RELATIVE_PATHS)
        set(CF_WEB_INPUT
            "${CF_WEB_SOURCE_DIR}/${CF_WEB_INPUT_RELATIVE_PATH}"
        )
        if(NOT EXISTS "${CF_WEB_INPUT}")
            message(FATAL_ERROR
                "Required camera firmware web input is missing: "
                "${CF_WEB_INPUT_RELATIVE_PATH}"
            )
        endif()
        file(SHA256 "${CF_WEB_INPUT}" CF_WEB_INPUT_SHA256)
        string(APPEND CF_WEB_CURRENT_MANIFEST
            "input\t${CF_WEB_INPUT_RELATIVE_PATH}\t${CF_WEB_INPUT_SHA256}\n"
        )
    endforeach()

    set(${CF_WEB_MANIFEST_RESULT} "${CF_WEB_CURRENT_MANIFEST}" PARENT_SCOPE)
endfunction()

function(cf_web_describe_manifest_difference
        CF_WEB_REASON_RESULT
        CF_WEB_PERSISTED_MANIFEST
        CF_WEB_CURRENT_MANIFEST)
    string(REGEX MATCHALL "input\t[^\r\n]+"
        CF_WEB_PERSISTED_INPUT_ENTRIES "${CF_WEB_PERSISTED_MANIFEST}")
    foreach(CF_WEB_INPUT_ENTRY IN LISTS CF_WEB_PERSISTED_INPUT_ENTRIES)
        string(REGEX REPLACE "^input\t([^\t\r\n]+)\t.*$" "\\1"
            CF_WEB_INPUT_PATH "${CF_WEB_INPUT_ENTRY}")
        string(FIND "${CF_WEB_CURRENT_MANIFEST}"
            "input\t${CF_WEB_INPUT_PATH}\t" CF_WEB_INPUT_FOUND)
        if(CF_WEB_INPUT_FOUND EQUAL -1)
            set(${CF_WEB_REASON_RESULT}
                "input '${CF_WEB_INPUT_PATH}' was removed or renamed"
                PARENT_SCOPE)
            return()
        endif()
    endforeach()

    string(REGEX MATCHALL "input\t[^\r\n]+"
        CF_WEB_CURRENT_INPUT_ENTRIES "${CF_WEB_CURRENT_MANIFEST}")
    foreach(CF_WEB_INPUT_ENTRY IN LISTS CF_WEB_CURRENT_INPUT_ENTRIES)
        string(REGEX REPLACE "^input\t([^\t\r\n]+)\t.*$" "\\1"
            CF_WEB_INPUT_PATH "${CF_WEB_INPUT_ENTRY}")
        string(FIND "${CF_WEB_PERSISTED_MANIFEST}"
            "input\t${CF_WEB_INPUT_PATH}\t" CF_WEB_INPUT_FOUND)
        if(CF_WEB_INPUT_FOUND EQUAL -1)
            set(${CF_WEB_REASON_RESULT}
                "input '${CF_WEB_INPUT_PATH}' was added or renamed"
                PARENT_SCOPE)
            return()
        endif()

        string(FIND "${CF_WEB_PERSISTED_MANIFEST}"
            "${CF_WEB_INPUT_ENTRY}" CF_WEB_ENTRY_FOUND)
        if(CF_WEB_ENTRY_FOUND EQUAL -1)
            set(${CF_WEB_REASON_RESULT}
                "input '${CF_WEB_INPUT_PATH}' content changed"
                PARENT_SCOPE)
            return()
        endif()
    endforeach()

    set(${CF_WEB_REASON_RESULT}
        "configured Node/npm tool identity or version changed"
        PARENT_SCOPE)
endfunction()

cf_web_create_input_manifest(CF_WEB_CURRENT_MANIFEST)

set(CF_WEB_REBUILD_REASON "")
if(NOT EXISTS "${CF_WEB_STAMP}")
    set(CF_WEB_REBUILD_REASON
        "this CMake build directory has not built the web artifacts"
    )
elseif(NOT EXISTS "${CF_WEB_MANIFEST}")
    set(CF_WEB_REBUILD_REASON
        "this CMake build directory has no persisted web input manifest"
    )
elseif(NOT EXISTS "${CF_WEB_OUTPUT_MANIFEST}")
    set(CF_WEB_REBUILD_REASON
        "this CMake build directory has no persisted web output manifest"
    )
else()
    cf_web_get_dist_inventory(CF_WEB_ACTUAL_OUTPUTS)
    if(NOT "${CF_WEB_ACTUAL_OUTPUTS}" STREQUAL
            "${CF_WEB_EXPECTED_OUTPUTS}")
        string(CONCAT CF_WEB_REBUILD_REASON
            "dist inventory is '${CF_WEB_ACTUAL_OUTPUTS}', expected "
            "'${CF_WEB_EXPECTED_OUTPUTS}'"
        )
    else()
        file(READ "${CF_WEB_MANIFEST}" CF_WEB_PERSISTED_MANIFEST)
        if(NOT "${CF_WEB_PERSISTED_MANIFEST}" STREQUAL
                "${CF_WEB_CURRENT_MANIFEST}")
            cf_web_describe_manifest_difference(
                CF_WEB_REBUILD_REASON
                "${CF_WEB_PERSISTED_MANIFEST}"
                "${CF_WEB_CURRENT_MANIFEST}"
            )
        else()
            file(READ "${CF_WEB_OUTPUT_MANIFEST}"
                CF_WEB_PERSISTED_OUTPUT_MANIFEST)
            cf_web_create_output_manifest(CF_WEB_CURRENT_OUTPUT_MANIFEST)
            if(NOT "${CF_WEB_PERSISTED_OUTPUT_MANIFEST}" STREQUAL
                    "${CF_WEB_CURRENT_OUTPUT_MANIFEST}")
                set(CF_WEB_REBUILD_REASON
                    "dist output content does not match persisted SHA-256"
                )
            endif()
        endif()
    endif()
endif()

if(CF_WEB_REBUILD_REASON STREQUAL "")
    message(STATUS
        "Camera firmware web artifacts match the local input manifest and dist"
    )
    return()
endif()

message(STATUS "Camera firmware web rebuild required: ${CF_WEB_REBUILD_REASON}")
message(STATUS "Running locked npm ci")
execute_process(
    COMMAND "${CF_WEB_NPM_EXECUTABLE}"
        ci --ignore-scripts --no-audit --no-fund
    WORKING_DIRECTORY "${CF_WEB_SOURCE_DIR}"
    RESULT_VARIABLE CF_WEB_NPM_CI_RESULT
)
if(NOT "${CF_WEB_NPM_CI_RESULT}" STREQUAL "0")
    message(FATAL_ERROR
        "Locked npm ci failed with exit code ${CF_WEB_NPM_CI_RESULT}. "
        "Run npm ci in ${CF_WEB_SOURCE_DIR} for full diagnostics."
    )
endif()

message(STATUS "Running locked npm run build")
execute_process(
    COMMAND "${CF_WEB_NPM_EXECUTABLE}" run build
    WORKING_DIRECTORY "${CF_WEB_SOURCE_DIR}"
    RESULT_VARIABLE CF_WEB_NPM_BUILD_RESULT
)
if(NOT "${CF_WEB_NPM_BUILD_RESULT}" STREQUAL "0")
    message(FATAL_ERROR
        "Locked npm run build failed with exit code "
        "${CF_WEB_NPM_BUILD_RESULT}. Run npm run build in "
        "${CF_WEB_SOURCE_DIR} for full diagnostics."
    )
endif()

cf_web_get_dist_inventory(CF_WEB_ACTUAL_OUTPUTS)
if(NOT "${CF_WEB_ACTUAL_OUTPUTS}" STREQUAL "${CF_WEB_EXPECTED_OUTPUTS}")
    message(FATAL_ERROR
        "npm run build produced dist inventory '${CF_WEB_ACTUAL_OUTPUTS}'; "
        "expected exactly '${CF_WEB_EXPECTED_OUTPUTS}'. The local build "
        "stamp and manifest were not updated."
    )
endif()

cf_web_create_input_manifest(CF_WEB_VALIDATED_MANIFEST)
if(NOT "${CF_WEB_VALIDATED_MANIFEST}" STREQUAL
        "${CF_WEB_CURRENT_MANIFEST}")
    message(FATAL_ERROR
        "Camera firmware web inputs changed while npm was building. "
        "The local stamp and manifest were not updated; rerun the build."
    )
endif()
cf_web_create_output_manifest(CF_WEB_VALIDATED_OUTPUT_MANIFEST)

file(MAKE_DIRECTORY "${CF_WEB_BINARY_DIR}")
file(WRITE "${CF_WEB_MANIFEST}" "${CF_WEB_VALIDATED_MANIFEST}")
file(WRITE "${CF_WEB_OUTPUT_MANIFEST}"
    "${CF_WEB_VALIDATED_OUTPUT_MANIFEST}")
file(TOUCH "${CF_WEB_STAMP}")
message(STATUS
    "Validated camera firmware web outputs: ${CF_WEB_ACTUAL_OUTPUTS}"
)
