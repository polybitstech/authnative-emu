cmake_minimum_required(VERSION 3.20)
project(authnative_emu LANGUAGES CXX)

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
)

target_compile_features(authnative_emu PUBLIC cxx_std_20)
set_target_properties(authnative_emu PROPERTIES PREFIX "")

add_executable(authnative_emu_test
        src/main.cpp
)

target_compile_features(authnative_emu_test PUBLIC cxx_std_20)