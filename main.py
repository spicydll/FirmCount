import binwalk

def main():
    binwalk.scan()
    for module in binwalk.scan('firmware/MERGE_IOT_V22.bin',signature=True,quiet=False, extract=True):
        print ("%s Results:" % module.name)

if __name__ == "__main__":
    main()