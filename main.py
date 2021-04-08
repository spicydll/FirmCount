#! ~/iot/env/bin/python

import scanner
import sys
from datetime import datetime
import argparse

"""
def doExtraction(file):
    stuff = binwalk.scan(file, quiet=True, extract=True, signature=True, directory="out/")
    print(stuff)

# functions: list of functions to check for
def scanForFunc(file):
    #testing: scan for printf
    print('R2 Scan:')
    r = r2pipe.open(file)
    r.cmd('aaa')
    file_info = r.cmdj('ij')
    funcs = r.cmdj('aflj')

    if file_info['core']['format'] == 'elf':
       print('Is elf lol')
       for f in funcs:
           print(f)
#        for f in funcs:
#            print(f['name'])
#            print(f)

"""

def main():
   # s = scanner.thread()
   # s.invokeReinit()

    p = argparse.ArgumentParser(description='Scans IoT Firmware for "Spicy" functions')
    

    #scanner.scanFile('bruh', ['sym.imp.printf', 'sym.imp.puts'])

if __name__ == "__main__":
    main()