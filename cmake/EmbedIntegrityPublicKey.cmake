include_guard(GLOBAL)

function(cf_embed_integrity_public_key output_variable)
  set(cf_integrity_development_public_key
      "${PROJECT_SOURCE_DIR}/config/integrity/dev-public-key.pem")
  if(NOT DEFINED CF_INTEGRITY_PUBLIC_KEY_FILE)
    set(CF_INTEGRITY_PUBLIC_KEY_FILE
        "${cf_integrity_development_public_key}"
        CACHE FILEPATH "Ed25519 public key embedded for integrity verification")
  endif()

  if(NOT EXISTS "${CF_INTEGRITY_PUBLIC_KEY_FILE}")
    message(FATAL_ERROR
        "CF_INTEGRITY_PUBLIC_KEY_FILE does not exist: "
        "${CF_INTEGRITY_PUBLIC_KEY_FILE}")
  endif()

  file(REAL_PATH "${CF_INTEGRITY_PUBLIC_KEY_FILE}"
      cf_integrity_selected_public_key)
  file(REAL_PATH "${cf_integrity_development_public_key}"
      cf_integrity_resolved_development_public_key)
  if(cf_integrity_selected_public_key STREQUAL
      cf_integrity_resolved_development_public_key)
    message(WARNING
        "Using the development integrity public key. Production builds must set "
        "CF_INTEGRITY_PUBLIC_KEY_FILE to the production Ed25519 public key.")
  endif()

  find_program(CF_OPENSSL_EXECUTABLE NAMES openssl REQUIRED)
  execute_process(
      COMMAND "${CF_OPENSSL_EXECUTABLE}" pkey -pubin -noout -in
              "${CF_INTEGRITY_PUBLIC_KEY_FILE}"
      RESULT_VARIABLE cf_integrity_public_key_result
      ERROR_VARIABLE cf_integrity_public_key_error
      OUTPUT_QUIET)
  if(NOT cf_integrity_public_key_result EQUAL 0)
    message(FATAL_ERROR
        "CF_INTEGRITY_PUBLIC_KEY_FILE is not a valid public key: "
        "${cf_integrity_public_key_error}")
  endif()

  execute_process(
      COMMAND "${CF_OPENSSL_EXECUTABLE}" pkey -pubin -noout -text -in
              "${CF_INTEGRITY_PUBLIC_KEY_FILE}"
      RESULT_VARIABLE cf_integrity_ed25519_key_result
      OUTPUT_VARIABLE cf_integrity_ed25519_key_text
      ERROR_VARIABLE cf_integrity_ed25519_key_error)
  if(NOT cf_integrity_ed25519_key_result EQUAL 0 OR
      NOT cf_integrity_ed25519_key_text MATCHES "ED25519")
    message(FATAL_ERROR
        "CF_INTEGRITY_PUBLIC_KEY_FILE must contain an Ed25519 public key: "
        "${cf_integrity_ed25519_key_error}")
  endif()

  file(READ "${CF_INTEGRITY_PUBLIC_KEY_FILE}" cf_integrity_public_key_pem)
  string(REPLACE "\\" "\\\\" cf_integrity_public_key_pem
      "${cf_integrity_public_key_pem}")
  string(REPLACE "\"" "\\\"" cf_integrity_public_key_pem
      "${cf_integrity_public_key_pem}")
  string(REPLACE "\r" "\\r" cf_integrity_public_key_pem
      "${cf_integrity_public_key_pem}")
  string(REPLACE "\n" "\\n\"\n\"" cf_integrity_public_key_pem
      "${cf_integrity_public_key_pem}")

  set(CF_INTEGRITY_PUBLIC_KEY_PEM "${cf_integrity_public_key_pem}")
  configure_file(
      "${PROJECT_SOURCE_DIR}/src/integrity/IntegrityTrustAnchor.cpp.in"
      "${CMAKE_CURRENT_BINARY_DIR}/IntegrityTrustAnchor.cpp"
      @ONLY)
  set(${output_variable} "${CMAKE_CURRENT_BINARY_DIR}/IntegrityTrustAnchor.cpp"
      PARENT_SCOPE)
endfunction()
