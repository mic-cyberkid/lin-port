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
        $<$<COMPILE_LANGUAGE:CXX,C>:/wd4996>          # Disable deprecation warnings
    )
    # Prevent min/max macros, disable heavy SQLite features, and suppress CRT warnings
    add_compile_definitions(NOMINMAX SQLITE_OMIT_FTS5 _CRT_SECURE_NO_WARNINGS)
    add_link_options(
        /LTCG            # Link Time Code Generation
        /OPT:REF         # Remove unused functions
        /OPT:ICF         # COMDAT folding
        /NODEFAULTLIB:libcmtd.lib # Avoid debug runtime conflict if any
    )
else()
    # GCC/Clang (MinGW)
    add_compile_options(
        $<$<COMPILE_LANGUAGE:CXX,C>:-Wall>
        $<$<COMPILE_LANGUAGE:CXX,C>:-Wextra>
        $<$<COMPILE_LANGUAGE:CXX,C>:-Wno-unknown-pragmas>
        $<$<COMPILE_LANGUAGE:CXX,C>:-Wno-unused-parameter>
        $<$<COMPILE_LANGUAGE:CXX,C>:-Wno-unused-variable>
        $<$<COMPILE_LANGUAGE:CXX,C>:-Wno-unused-but-set-variable>
        $<$<COMPILE_LANGUAGE:CXX,C>:-Wno-comment>
    )
    # Target Win7+ and disable some annoying warnings
    add_compile_definitions(_WIN32_WINNT=0x0601 NOMINMAX)
endif()
