cmake_minimum_required(VERSION 3.25)
project(erikslund_mmproxy VERSION 0.1.0 LANGUAGES CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "mmproxy requires Linux transparent sockets and epoll")
endif()

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(NATIVE_ARCH "Tune Release for the build machine's CPU" OFF)
add_compile_options(-Wall -Wextra -Wshadow -fstack-protector-strong -fstack-clash-protection)
add_compile_options($<$<CONFIG:Release>:-flto> $<$<CONFIG:Release>:-ffunction-sections>
                    $<$<CONFIG:Release>:-fdata-sections>)
add_compile_definitions($<$<CONFIG:Release>:_FORTIFY_SOURCE=3>
                        $<$<CONFIG:Release>:_GLIBCXX_ASSERTIONS>)
add_link_options(-Wl,-z,relro,-z,now $<$<CONFIG:Release>:-flto=auto>
                 $<$<CONFIG:Release>:-Wl,--gc-sections>)
add_compile_options(-fPIE)
add_link_options(-pie)
add_link_options(-static-libstdc++ -static-libgcc)
if(NATIVE_ARCH)
    add_compile_options($<$<CONFIG:Release>:-march=native>)
endif()

find_package(Threads REQUIRED)

file(GLOB_RECURSE CORE_SOURCES CONFIGURE_DEPENDS src/mmproxy/*.cpp)
add_library(mmproxy_core STATIC ${CORE_SOURCES})
target_include_directories(mmproxy_core PUBLIC src)
target_compile_definitions(mmproxy_core PUBLIC MMPROXY_VERSION="${PROJECT_VERSION}")
target_link_libraries(mmproxy_core PUBLIC Threads::Threads)

add_executable(erikslund-mmproxy src/main.cpp)
target_link_libraries(erikslund-mmproxy PRIVATE mmproxy_core)
install(TARGETS erikslund-mmproxy RUNTIME DESTINATION bin)

include(CTest)
if(BUILD_TESTING)
    find_package(doctest CONFIG REQUIRED)
    file(GLOB TEST_SOURCES CONFIGURE_DEPENDS tests/*.cpp)
    add_executable(mmproxy_tests ${TEST_SOURCES})
    target_link_libraries(mmproxy_tests PRIVATE mmproxy_core doctest::doctest)
    add_test(NAME mmproxy_tests COMMAND mmproxy_tests)
endif()
