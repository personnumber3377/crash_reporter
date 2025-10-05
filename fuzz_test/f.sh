#!/bin/sh

afl-fuzz -i in -o out -- ./main

