cmake_minimum_required(VERSION 3.2)
project(mdns C)

add_library(${PROJECT_NAME} mdns.c)

add_executable(${PROJECT_NAME}-test mdns-test.c)
target_link_libraries(${PROJECT_NAME}-test ${PROJECT_NAME})