cmake_minimum_required(VERSION 3.23)
project(exports)

set(CMAKE_CXX_STANDARD 20 REQUIRED)

add_executable(exports pe_exports.cpp ctpl.h)

