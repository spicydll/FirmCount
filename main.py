import binwalk
import r2pipe
import sys

def doExtraction(file):
    for module in binwalk.scan(file, quiet=True, extract=True, signature=True, directory="out/"):
        print ("%s Results:" % module.name)
        for result in module.results:
            print ("\t%s    0x%.8X    %s" % (result.file.path, result.offset, result.description))


def scanForFunc(file, functions):
    pass
    

def main():
    doExtraction(sys.argv[1])
  #  scanForFunc()

if __name__ == "__main__":
    main()