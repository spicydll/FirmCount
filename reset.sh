#!/bin/bash

python main.py db reinit -f
python main.py func add strcpy 'Buffer Overflow'
python main.py func add strcat 'Buffer Overflow'
python main.py func add gets 'Buffer Overflow'
python main.py func add sprintf 'Buffer Overflow'
python main.py func add strlen 'Buffer Overflow'