@echo off
gcc -Ofast -s -o pngasteg.exe pngasteg.c -Iinclude -Llib -lpng12 -l:zlib1.dll
copy lib\*.dll .