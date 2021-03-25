import binwalk
import r2pipe
import database
import hashlib

def getSignature(file_path):
    hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096),b""):
            hash.update(block)
    return hash.hexdigest()


def scanImage(image_path):
    signature,work_path = doExtraction(image_path)
    


def doExtraction(file_path):
    signature = getSignature(file_path)
    output_dir = "out/{}".format(signature)
    binwalk.scan(file_path, quiet=True, extract=True, signature=True, directory=output_dir)
    return signature,output_dir
