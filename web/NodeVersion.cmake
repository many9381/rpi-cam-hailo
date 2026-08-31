function(cf_node_version_is_supported CF_VERSION CF_RESULT)
    set(CF_SUPPORTED FALSE)
    if(CF_VERSION MATCHES "^[0-9]+(\\.[0-9]+)*$")
        if((NOT CF_VERSION VERSION_LESS "20.19.0" AND
                CF_VERSION VERSION_LESS "21.0.0") OR
                NOT CF_VERSION VERSION_LESS "22.12.0")
            set(CF_SUPPORTED TRUE)
        endif()
    endif()
    set(${CF_RESULT} ${CF_SUPPORTED} PARENT_SCOPE)
endfunction()
