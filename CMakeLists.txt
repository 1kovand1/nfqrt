cmake_minimum_required(VERSION 3.5.0)
project(nfqrt VERSION 0.1.0 LANGUAGES C)

add_executable(nfqrt nfqrt.c parse.c)
target_link_libraries(nfqrt netfilter_queue)