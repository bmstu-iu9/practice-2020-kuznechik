#!/bin/bash 
gcc -ffast-math -march=armv8-a+simd+crypto -Wall -std=gnu11 -O3 tables.c mgm128.c main.c -o mgm_test
