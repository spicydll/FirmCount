#! ~/iot/env/bin/python

import scanner
import sys
from datetime import datetime
import argparse
from pprint import pprint

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

def addfunction(args):
    s = scanner.thread()
    s.db.addVulnFunction(args.name, args.description)

def deletefunction(args):
    pass

def listfunctions(args):
    s = scanner.thread()
    s.db.functionList()

def scan(args):
    
    # Check to get all information
    if not args.force:
        if args.name == None:
            args.name = input("Image Name: ")
        if args.manufacturer == None:
            args.manufacturer = input("Manufacturer: ")
        if args.date == None:
            args.date = datetime.strptime(input("Date (YYYY-MM-DD): "), '%Y-%m-%d')
    
    s = scanner.thread()
    s.scanImage(args.path, args.manufacturer, args.date, args.name, args.no_progress, args.keep_dir)


def reinit(args):
    if (args.force):
        s = scanner.thread()
        s.invokeReinit()
    else:
        conf = input("Reinitialize database? (ALL DATA WILL BE LOST) [Y/n]: ")
        if conf == 'Y' or conf == 'y':
            s = scanner.thread()
            s.invokeReinit()

def imgresult(args):
    s = scanner.thread()
    id = s.db.getImageIdFromName(args.name)
    s.db.imageSummary(id)
    s.db.detectionSummary(id)

def imgdel(args):
    if args.force or (input("Delete image? (THIS CANNOT BE UNDONE!) [Y/n]: ").lower() == 'y'):
        s = scanner.thread()
        id = s.db.getImageIdFromName(args.name)
        s.db.deleteImage(id)

def imglist(args):
    s = scanner.thread()
    s.db.imageList()

def prog_action(arg_obj):
    
    action_switch = {
        'reinit': reinit,
        'scan': scan,
        'addfunction': addfunction,
        'imgresult': imgresult,
        'imgdel': imgdel,
        'imglist': imglist,
        'listfunctions': listfunctions
    }

    if arg_obj.act in action_switch:
        return action_switch[arg_obj.act](arg_obj)
    else:
        print('Not implemented')
        return None

def makeargs():
    p = argparse.ArgumentParser(description='Scans IoT Firmware for "Spicy" functions')
    cmdsubp = p.add_subparsers(help='Command to run')

    func_sp = cmdsubp.add_parser('func', help='Commands to define which functions to scan for')
    funcsubps = func_sp.add_subparsers(help='Function command to run')

    addfunc_sp = funcsubps.add_parser('add')
    addfunc_sp.add_argument('name', type=str)
    addfunc_sp.add_argument('description', type=str)
    addfunc_sp.set_defaults(act='addfunction')

    removefunc_sp = funcsubps.add_parser('remove')
    removefunc_sp.add_argument('name', type=str)
    removefunc_sp.set_defaults(act='deletefunction')
    
    listfunc_sp = funcsubps.add_parser('list')
    listfunc_sp.set_defaults(act='listfunctions')

    scan_sp = cmdsubp.add_parser('scan', help='Scan a firmware image')
    scan_sp.add_argument('-n', '--name', type=str, help='Name for image in database')
    scan_sp.add_argument('-m', '--manufacturer', type=str, help='Name or database id of Manufacturer of Firmware Image')
    scan_sp.add_argument('-d', '--date', type=lambda s: datetime.strptime(s, '%Y-%m-%d'), help='Release date of firmware in YYYY-MM-DD')
    scan_sp.add_argument('path', type=str, help='Path to firmware image to scan')
    scan_sp.add_argument('-f', '--force', action='store_true', help='Force no interaction')
    scan_sp.add_argument('-P', '--no-progress', action='store_false', help='Makes progress bar not cool and stuff')
    scan_sp.add_argument('-k', '--keep-dir', action='store_true', help='Keep extraction directory after scanning (delete before next scan!)')
    scan_sp.set_defaults(act='scan')

    image_sp = cmdsubp.add_parser('image', help='Retrieve and manage image data')
    imagesubps = image_sp.add_subparsers(help='Operation to perform')

    imglist_sp = imagesubps.add_parser('list', help='List all images in database')
    imglist_sp.set_defaults(act='imglist')

    imgresult_sp = imagesubps.add_parser('show', help='Print results of scan')
    imgresult_sp.add_argument('name', type=str, help='Name assigned to image in database')
    imgresult_sp.set_defaults(act='imgresult')

    imgreset_sp = imagesubps.add_parser('delete', help='Removes all entries associated with this image in the database')
    imgreset_sp.add_argument('-f', '--force', action='store_true', help='Force delete without confirmation')
    imgreset_sp.add_argument('name', type=str, help='Name of image to delete')
    imgreset_sp.set_defaults(act='imgdel')

    database_sp = cmdsubp.add_parser('db', help='Retrieve data and manage the database')
    dbsubps = database_sp.add_subparsers(help='Database action to perform')

    reinit_sp = dbsubps.add_parser('reinit', help='Reinitialize the database (ALL DATA LOST)')
    reinit_sp.add_argument('-f', '--force', action='store_true')
    reinit_sp.set_defaults(act='reinit')

    return p

def main():
   # s = scanner.thread()
   # s.invokeReinit()

    p = makeargs()
    
    result = p.parse_args()
    done = prog_action(result)
    #pprint(done)

    #print()
    #pprint(result)

    #pprint(scanner.scanFile('bruh', ['sym.imp.printf', 'sym.imp.puts']))

if __name__ == "__main__":
    main()