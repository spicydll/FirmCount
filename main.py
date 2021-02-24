import binwalk
import r2pipe
import sys
import logging

def doExtraction(file):
    for module in binwalk.scan(file, quiet=True, extract=True, signature=True, directory="out/"):
        print ("%s Results:" % module.name)
        for result in module.results:
            print ("\t%s    0x%.8X    %s" % (result.file.path, result.offset, result.description))

# functions: list of functions to check for
def scanForFunc(file):
    #testing: scan for printf
    print('R2 Scan:')
    r = r2pipe.open(file)
    r.cmd('aa')
    file_info = r.cmdj('ij')
    funcs = r.cmdj('aflj')
    
    if file_info['core']['format'] == 'elf':
        print('Is elf lol')



def main():
    doExtraction(sys.argv[1])
    scanForFunc('out/_c7v5_[20201120-rel50406]_2020-11-20_14.00.44.bin.extracted/squashfs-root/usr/bin/ledctrl')
  #  scanForFunc()

if __name__ == "__main__":
    main()