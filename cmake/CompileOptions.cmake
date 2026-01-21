# Set global compile options
if(MSVC)
    # Warning level 4, treat warnings as errors
    add_compile_options(/W4 /WX)
    # Enable security checks
    add_compile_options(/GS)
    # Enable exception handling
    add_compile_options(/EHsc)
    # Strict conformance
    add_compile_options(/permissive-)
else()
    # GCC/Clang
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()
