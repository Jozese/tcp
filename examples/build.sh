#!/bin/bash
clang++ ../tcp.cxx "$1" -o tcp_example \
  -Werror -Wall -Wextra -pedantic-errors \
   -O3 -std=c++20 -lcrypto -lssl
