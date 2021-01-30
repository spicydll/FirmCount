import binwalk
import sys

def doExtraction(file):
    for module in binwalk.scan(file, signature=True, quiet=True, extract=True):
        print ("%s Results:" % module.name)
        for result in module.results:
            print ("\t%s    0x%.8X    %s" % (result.file.path, result.offset, result.description))

def main():
    doExtraction(sys.argv[1])

if __name__ == "__main__":
    main()