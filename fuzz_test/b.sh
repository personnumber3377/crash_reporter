#!/bin/sh


afl-clang-fast -fsanitize=address main.c -o main

