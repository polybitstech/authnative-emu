cmake_minimum_required(VERSION 3.20)
project(authnative_emu LANGUAGES CXX)

if (NOT MSVC)
    message(FATAL_ERROR "This project must be built with MSVC.")
endif()

add_library(authnative_emu SHARED
        include/authnative/constants.h
        include/authnative/crypto.h
        include/authnative/utils.h
        src/core.cpp
)

target_include_directories(authnative_emu PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(authnative_emu PRIVATE
        bcrypt
        wbemuuid
        comsuppw
)

target_compile_features(authnative_emu PUBLIC cxx_std_20)

add_executable(authnative_emu_test
        src/main.cpp
)

target_compile_features(authnative_emu_test PUBLIC cxx_std_20)