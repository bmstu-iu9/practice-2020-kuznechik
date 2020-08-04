#!/bin/bash 
gcc -std=gnu11 -O3 -msse4.2 -msse4.1 -msse3 -msse2 -mpclmul tables.c mgm128.c main.c -o mgm_test
