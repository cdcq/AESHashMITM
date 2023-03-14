cmake_minimum_required(VERSION 3.24)
project(AESHashMITM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

set(LOG_SRC log.cpp log.h)
set(AES_SRC aes.cpp aes.h)
set(CALCULATOR_SRC calculator.cpp calculator.h)
set(MITM_4_ROUND_SRC mitm_4_round.cpp mitm_4_round.h)
set(MITM_7_ROUND_SRC mitm_7_round.cpp mitm_7_round.h)
set(MITM_7_PLUS_SRC mitm_7_plus.cpp mitm_7_plus.h)
set(TEST_SRC test.cpp)

add_executable(
        TEST
        ${LOG_SRC}
        ${AES_SRC}
        ${CALCULATOR_SRC}
        ${MITM_4_ROUND_SRC}
        ${MITM_7_ROUND_SRC}
        ${MITM_7_PLUS_SRC}
        ${TEST_SRC}
)
