#! ~/iot/env/bin/python

import scanner
import sys

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
    scanner.scanImage(sys.argv[1])
    #scanForFunc('out/_c7v5_[20201120-rel50406]_2020-11-20_14.00.44.bin.extracted/squashfs-root/usr/bin/ledcli')
  #  scanForFunc()

if __name__ == "__main__":
    main()