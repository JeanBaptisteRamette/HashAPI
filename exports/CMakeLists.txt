cmake_minimum_required(VERSION 3.23)
project(exports)

set(CMAKE_CXX_STANDARD 20 REQUIRED)

add_executable(exports pe_exports.cpp ctpl.h)

find_package(PythonLibs REQUIRED)
include_directories(${PYTHON_INCLUDE_DIRS})
target_link_libraries(exports ${PYTHON_LIBRARIES})