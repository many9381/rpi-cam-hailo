if(NOT DEFINED SERVICE_LIBRARY OR NOT DEFINED SERVICE_REGISTRY_HEADER OR
   NOT DEFINED NM_EXECUTABLE)
  message(FATAL_ERROR "service production surface test arguments are missing")
endif()

file(READ "${SERVICE_REGISTRY_HEADER}" registry_header)
if(registry_header MATCHES "TerminalElection|TryBeginTerminalElection")
  message(FATAL_ERROR "session terminal election details are exposed")
endif()

execute_process(
  COMMAND "${NM_EXECUTABLE}" -g --defined-only "${SERVICE_LIBRARY}"
  RESULT_VARIABLE nm_result
  OUTPUT_VARIABLE nm_output
  ERROR_VARIABLE nm_error
)
if(NOT nm_result EQUAL 0)
  message(FATAL_ERROR "nm failed: ${nm_error}")
endif()
if(nm_output MATCHES "ForTesting")
  message(FATAL_ERROR "production service library defines test controls")
endif()
