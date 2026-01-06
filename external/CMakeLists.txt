find_program(CARGO_EXECUTABLE cargo REQUIRED)

# determine build type
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CARGO_BUILD_FLAG "")
    set(CARGO_TARGET_DIR "debug")
else()
    set(CARGO_BUILD_FLAG "--release")
    set(CARGO_TARGET_DIR "release")
endif()

# build rust library
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/risc0-ffi/target/${CARGO_TARGET_DIR}/librisc0_ffi.a
    COMMAND ${CARGO_EXECUTABLE} build ${CARGO_BUILD_FLAG}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/risc0-ffi
    COMMENT "Building risc0_ffi rust library with cargo (${CMAKE_BUILD_TYPE})"
)

# create cmake target
add_custom_target(risc0_ffi_build ALL
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/risc0-ffi/target/${CARGO_TARGET_DIR}/librisc0_ffi.a
)

# import libary
add_library(risc0_ffi STATIC IMPORTED GLOBAL)
set_target_properties(risc0_ffi PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/risc0-ffi/target/${CARGO_TARGET_DIR}/librisc0_ffi.a
)
target_include_directories(risc0_ffi INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/risc0-ffi
)
add_dependencies(risc0_ffi risc0_ffi_build)
