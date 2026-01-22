# Set global compile options
if(MSVC)
    add_compile_options(
        $<$<COMPILE_LANGUAGE:CXX,C>:/W4>              # Warning level 4
        $<$<COMPILE_LANGUAGE:CXX,C>:/WX>              # Treat warnings as errors
        $<$<COMPILE_LANGUAGE:CXX,C>:/std:c++20>       # C++20 standard
        $<$<COMPILE_LANGUAGE:CXX,C>:/permissive->     # Strict conformance
        $<$<COMPILE_LANGUAGE:CXX,C>:/D_WIN32_WINNT=0x0601> # Target Windows 7 (or later)
        $<$<COMPILE_LANGUAGE:CXX,C>:/Os>              # Favor size
        $<$<COMPILE_LANGUAGE:CXX,C>:/GL>              # Whole Program Optimization
        $<$<COMPILE_LANGUAGE:CXX,C>:/MT>              # Static runtime
        $<$<COMPILE_LANGUAGE:CXX,C>:/GS->             # Disable buffer security check
        $<$<COMPILE_LANGUAGE:CXX,C>:/EHsc>            # Enable exception handling
    )
    # Prevent min/max macros and disable heavy SQLite features
    add_compile_definitions(NOMINMAX SQLITE_OMIT_FTS5)
    add_link_options(
        /LTCG            # Link Time Code Generation
        /OPT:REF         # Remove unused functions
        /OPT:ICF         # COMDAT folding
        /NODEFAULTLIB:libcmtd.lib # Avoid debug runtime conflict if any
    )
else()
    # GCC/Clang
    add_compile_options($<$<COMPILE_LANGUAGE:CXX,C>:-Wall> $<$<COMPILE_LANGUAGE:CXX,C>:-Wextra> $<$<COMPILE_LANGUAGE:CXX,C>:-Wpedantic> $<$<COMPILE_LANGUAGE:CXX,C>:-Werror>)
endif()
