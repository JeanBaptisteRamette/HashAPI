cmake_minimum_required(VERSION 3.23)
project(implementation)

set(CMAKE_CXX_STANDARD 20 REQUIRED)
add_executable(implementation api_hash.cpp ntdef64.h)

