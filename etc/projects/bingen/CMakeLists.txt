cmake_minimum_required(VERSION 3.12)
project(bingen LANGUAGES CXX)
option(ENABLE_TLS "Whether to generate TLS in resulting binary" ON)

if(ENABLE_TLS)
    add_definitions(-DENABLE_TLS)
endif()

set(CMAKE_SYSTEM_NAME Windows)

add_executable(bin WIN32 "main.cc")
set_target_properties(bin PROPERTIES LANGUAGE C)
target_compile_options(bin PRIVATE
    /GS- # Disable generation of stack check handlers
    /GS # Enable whole program optimization
)
target_link_options(bin PRIVATE
    /ENTRY:main # Explicit entry symbol since there are no CRT/libs to be linked
    /MANIFEST:NO # Disable manifest
    /NODEFAULTLIB # No libs; we want a pure binary
    /FIXED # No relocs
    /DYNAMICBASE:NO # No ASLR
    /SAFESEH # No unwinds
    /MERGE:.data=.text /MERGE:.CRT=.text /MERGE:.tls=.text # Combine sections to avoid paddings
)
