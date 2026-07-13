include("${CMAKE_CURRENT_LIST_DIR}/NodeVersion.cmake")

find_program(NODE_EXECUTABLE NAMES node REQUIRED)
execute_process(
    COMMAND "${NODE_EXECUTABLE}" --version
    RESULT_VARIABLE CF_NODE_VERSION_RESULT
    OUTPUT_VARIABLE CF_NODE_VERSION_OUTPUT
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_VARIABLE CF_NODE_VERSION_ERROR
    ERROR_STRIP_TRAILING_WHITESPACE
)
if(NOT CF_NODE_VERSION_RESULT EQUAL 0)
    message(FATAL_ERROR
        "Unable to run Node.js: ${CF_NODE_VERSION_ERROR}"
    )
endif()
string(REGEX REPLACE "^v" "" CF_NODE_VERSION "${CF_NODE_VERSION_OUTPUT}")
cf_node_version_is_supported("${CF_NODE_VERSION}" CF_NODE_SUPPORTED)
if(NOT CF_NODE_SUPPORTED)
    message(FATAL_ERROR
        "Node.js ^20.19.0 or >=22.12.0 is required; "
        "found ${CF_NODE_VERSION_OUTPUT}"
    )
endif()

find_program(NPM_EXECUTABLE NAMES npm REQUIRED)
execute_process(
    COMMAND "${NPM_EXECUTABLE}" --version
    RESULT_VARIABLE CF_NPM_VERSION_RESULT
    OUTPUT_VARIABLE CF_NPM_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_VARIABLE CF_NPM_VERSION_ERROR
    ERROR_STRIP_TRAILING_WHITESPACE
)
if(NOT CF_NPM_VERSION_RESULT EQUAL 0 OR
        NOT CF_NPM_VERSION MATCHES "^[0-9]+(\\.[0-9]+)*$")
    message(FATAL_ERROR
        "Unable to run npm: ${CF_NPM_VERSION_ERROR}"
    )
endif()

set(CF_WEB_OUTPUTS
    "${CMAKE_CURRENT_SOURCE_DIR}/dist/index.html"
    "${CMAKE_CURRENT_SOURCE_DIR}/dist/app.js"
    "${CMAKE_CURRENT_SOURCE_DIR}/dist/styles.css"
)
set(CF_WEB_STAMP
    "${CMAKE_CURRENT_BINARY_DIR}/camera_firmware_web.stamp"
)
set(CF_WEB_MANIFEST
    "${CMAKE_CURRENT_BINARY_DIR}/camera_firmware_web.inputs.sha256"
)
set(CF_WEB_OUTPUT_MANIFEST
    "${CMAKE_CURRENT_BINARY_DIR}/camera_firmware_web.outputs.sha256"
)

add_custom_target(camera_firmware_web ALL
    COMMAND "${CMAKE_COMMAND}"
        "-DCF_WEB_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
        "-DCF_WEB_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
        "-DCF_WEB_NODE_EXECUTABLE=${NODE_EXECUTABLE}"
        "-DCF_WEB_NODE_VERSION=${CF_NODE_VERSION}"
        "-DCF_WEB_NPM_EXECUTABLE=${NPM_EXECUTABLE}"
        "-DCF_WEB_NPM_VERSION=${CF_NPM_VERSION}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/BuildWeb.cmake"
    BYPRODUCTS
        ${CF_WEB_OUTPUTS}
        "${CF_WEB_STAMP}"
        "${CF_WEB_MANIFEST}"
        "${CF_WEB_OUTPUT_MANIFEST}"
    COMMENT "Validating camera firmware web artifacts"
    VERBATIM
)

if(BUILD_TESTING)
    add_test(
        NAME WebAppTest
        COMMAND "${NPM_EXECUTABLE}" test
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    )
endif()

install(FILES ${CF_WEB_OUTPUTS}
    DESTINATION share/camera-firmware/web
)
