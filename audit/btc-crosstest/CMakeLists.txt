cmake_minimum_required(VERSION 3.22)
project(BtcCrossTest LANGUAGES CXX)

# Core's C++ standard is directory-scoped when embedded, so apply it to this sibling target too.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(BITCOIN_SOURCE_DIR "" CACHE PATH "Path to a Bitcoin Core source checkout")
if(NOT EXISTS "${BITCOIN_SOURCE_DIR}/src/psbt.h")
  message(FATAL_ERROR "Set BITCOIN_SOURCE_DIR to a Bitcoin Core source checkout with PSBTv2")
endif()

# Only Core's in-process libraries are needed; keep the bridge independent of node state and RPC.
set(BUILD_BITCOIN_BIN OFF CACHE BOOL "" FORCE)
set(BUILD_DAEMON OFF CACHE BOOL "" FORCE)
set(BUILD_GUI OFF CACHE BOOL "" FORCE)
set(BUILD_CLI OFF CACHE BOOL "" FORCE)
set(BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(BUILD_TX OFF CACHE BOOL "" FORCE)
set(BUILD_UTIL OFF CACHE BOOL "" FORCE)
set(BUILD_UTIL_CHAINSTATE OFF CACHE BOOL "" FORCE)
set(BUILD_KERNEL_LIB OFF CACHE BOOL "" FORCE)
set(ENABLE_WALLET OFF CACHE BOOL "" FORCE)
set(ENABLE_EXTERNAL_SIGNER OFF CACHE BOOL "" FORCE)
set(ENABLE_IPC OFF CACHE BOOL "" FORCE)
set(WITH_EMBEDDED_ASMAP OFF CACHE BOOL "" FORCE)
set(INSTALL_MAN OFF CACHE BOOL "" FORCE)
# The selected checkout may inherit a host ccache directory that this standalone build cannot use.
set(WITH_CCACHE OFF CACHE BOOL "" FORCE)

add_subdirectory("${BITCOIN_SOURCE_DIR}" core EXCLUDE_FROM_ALL)

add_executable(btc-crosstest main.cpp)
target_include_directories(btc-crosstest PRIVATE
  "${BITCOIN_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_BINARY_DIR}/core/src"
)
target_link_libraries(btc-crosstest PRIVATE core_interface bitcoin_common bitcoin_util)

enable_testing()
find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_test(NAME btc-crosstest
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/test.py"
          "$<TARGET_FILE:btc-crosstest>"
)
