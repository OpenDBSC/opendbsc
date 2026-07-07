cmake_minimum_required(VERSION 3.16)
project(opendbsc C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(FetchContent)

FetchContent_Declare(
    uuidv7
    GIT_REPOSITORY https://github.com/LiosK/uuidv7-h.git
    GIT_TAG        v0.1.6
)

FetchContent_Declare(
    cjson
    GIT_REPOSITORY https://github.com/DaveGamble/cJSON.git
    GIT_TAG        v1.7.19
)

set(ENABLE_CJSON_TEST OFF CACHE BOOL "" FORCE)
set(ENABLE_CJSON_UTILS OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(uuidv7 cjson)

# Vendored Redis client.
set(DISABLE_TESTS ON CACHE BOOL "" FORCE)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/libs/hiredis)

# System dependencies.
find_package(PkgConfig REQUIRED)
pkg_check_modules(SQLite3 REQUIRED sqlite3)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_library(opendbsc
    src/algo/algo.c
    src/protocol/header.c
    src/protocol/instruction.c
    src/protocol/jwt.c
    src/session/session.c
    src/store/memory.c
    src/store/redis.c
    src/store/sqlite.c
    src/manager/manager.c
    src/wrapper/http.c
    libs/mongoose/mongoose.c
)

target_include_directories(opendbsc
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/libs/mongoose
        ${uuidv7_SOURCE_DIR}
        ${cjson_SOURCE_DIR}
        ${SQLite3_INCLUDE_DIRS}
)

target_link_libraries(opendbsc
    PUBLIC
        cjson
        hiredis::hiredis
        OpenSSL::SSL
        OpenSSL::Crypto
        ${SQLite3_LIBRARIES}
        Threads::Threads
)

# Use OpenSSL as the mongoose TLS backend.
target_compile_definitions(opendbsc PRIVATE MG_TLS=MG_TLS_OPENSSL)

# OpenSSL 3.x marks EC/RSA low-level APIs as deprecated. Suppress the noise
# while keeping the implementation compatible with OpenSSL 1.1 and 3.x.
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(opendbsc PRIVATE -Wno-deprecated-declarations)
endif()

# Example server executable.
add_executable(server examples/server.c)
target_link_libraries(server PRIVATE opendbsc)
