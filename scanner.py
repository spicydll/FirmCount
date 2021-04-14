import binwalk
import r2pipe
import database
import hashlib
from os import walk
from os.path import join
from os.path import split
from os.path import islink
import shutil
from pprint import pprint # for debug stuff
import progressbar
import pdb

# Might rename class to scanner, especially if multithreading is not achieved
# Contains all instance specific stuff
class thread:
    def __init__(self):
        self.db = database.iotDB()

    def invokeReinit(self):
        self.db.reinit()

    def scanImage(self, image_path, man_name, release_date, name):
        # extract
        try:
            signature,work_path = doExtraction(image_path)

            funcs_to_scan = self.getFuncsToScanFor_Formatted()

            # report extraction
            self.db.newImage(signature, man_name, release_date, name)

            # walk extracted files
            files = []
            displayfiles = []
            for root, _, f in walk(work_path):
                for item in f:
                    full_path = join(root, item)
                    if (not islink(full_path)):
                        files.append(full_path)
                        displayfiles.append(join('/'.join(root.split('/')[3:]), item))

            with progressbar.ProgressBar(max_value=len(files), redirect_stdout=True) as p:
                p.start()
                for i, file in enumerate(files):
                    p.update(i)
                    print('Checking: "{}"'.format(displayfiles[i]))
                    check, r = fileCheck(file)
                    if (check is not False):
                        file_signature = check
                        is_scanned = self.db.checkImageFileScanned(signature, file_signature, displayfiles[i])

                        if (not is_scanned):
                            print('Scanning: "{0}"'.format(displayfiles[i]))
                            detections = scanFile(file, funcs_to_scan, r)
                            self.db.insertDetections(file_signature, detections)
                            print('Complete: "{}"'.format(displayfiles[i]))
                        else:
                            print('Skipping: Previously Scanned')
                    else:
                        print('Skipping: Not an ELF')
                p.finish()
            
            print('Results: {}'.format(name))
            self.db.prettyPrintCursur()
        finally:
            shutil.rmtree('out/')
    
    def getFuncsToScanFor_Formatted(self):
        functions = self.db.getAllVulnFunctions()
        functions_fmt = []
        for func in functions:
            functions_fmt.append('sym.imp.{}'.format(func['name']))

        return functions_fmt

# checks if file is elf and returns its signature
def fileCheck(path):
    if (islink(path)):
        return False, None
    try:
        r = r2pipe.open(path, flags=['-2'])
            #r.cmd('aaa')

        # check if file type is elf or elf64
        # return False if not
        file_type = r.cmdj('ij')['core']['format']
        if ('elf' not in file_type):
            return False, None
        else:
            return getSignature(path), r
    except BrokenPipeError:
        r.quit()
        return False, None


# Does not do database stuff !
# target_funcs should be in sym.imp.<function> format
# returns False if not an elf file
def scanFile(path, target_funcs, radare_obj):
    detections = dict()
    r = radare_obj
    r.cmd('aaa')

    # check if file type is elf or elf64
    # return False if not
    file_type = r.cmdj('ij')['core']['format']
    if ('elf' not in file_type):
        #r.close()
        return # maybe do a log here but should be impossible

    # Scan for our spicy funtions
    file_imports = r.cmdj('aflj')
    if file_imports != None:
        for func in file_imports:
            name = func['name']
            # check if function name one we need to scan
            if (name in target_funcs):
                detections[name] = []
                # check for all calls for our spicy function
                refs = r.cmdj('axtj@{}'.format(name))
                for ref in refs:
                    detections[name].append(ref['from'])
        
    ## debug pprint(detections)

    r.quit()
    return detections


# maybe replace with more efficient hash function
def getSignature(file_path):
    hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096),b""):
            hash.update(block)
    return hash.hexdigest()

def doExtraction(file_path):
    signature = getSignature(file_path)
    output_dir = "out/{}".format(signature)
    binwalk.scan(file_path, quiet=True, extract=True, signature=True, directory=output_dir)
    return signature,output_dir
