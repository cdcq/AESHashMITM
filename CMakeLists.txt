cmake_minimum_required(VERSION 3.24)
project(AESHashMITM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(AES_SRC aes.cpp aes.h)
set(MITM_4_ROUND_SRC mitm_4_round.cpp mitm_4_round.h)
set(TEST_SRC test.cpp)

add_executable(
        TEST
        ${AES_SRC}
        ${MITM_4_ROUND_SRC}
        ${TEST_SRC}
)
