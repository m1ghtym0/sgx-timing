#!/bin/bash

printf "Stop Counters\n"
./pmctest stopcounters 1 9 100 311
printf "Clean-up PMC-Testsuite\n"
make clean
cd driver
printf "Uninstall driver\n"
./uninstall.sh
printf "Clean-up driver LKM\n"
make clean
