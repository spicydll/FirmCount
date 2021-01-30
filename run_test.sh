#!/bin/bash

rm -rf ./out/*

for file in firmware/*; do
    echo "==============================="
    echo "Executing: python main.py $file"
    echo "==============================="
    python main.py $file
    echo "==============================="
    echo "End: python main.py $file"
    echo "==============================="
    echo
done