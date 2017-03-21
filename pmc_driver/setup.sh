#!/bin/bash

printf "Build driver LKM\n"
cd driver
make
printf "Install driver\n"
./install.sh
cd ..
printf "Build PMC-Testsuite\n"
make
printf "Start Counters\n"
./pmctest startcounters 1 9 100 311
