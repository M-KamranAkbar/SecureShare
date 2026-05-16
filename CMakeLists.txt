cmake_minimum_required(VERSION 3.20)
project(SecureShare VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(Qt6 REQUIRED COMPONENTS Core Widgets Network)

include_directories(include)

add_subdirectory(src/server)
add_subdirectory(src/client)
add_subdirectory(src/auth)
add_subdirectory(src/crypto)
add_subdirectory(src/storage)
add_subdirectory(src/gui)
