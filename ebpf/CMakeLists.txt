cmake_minimum_required(VERSION 3.30)
project(bpfdsr C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(
        encoder
        encoder.c
)
