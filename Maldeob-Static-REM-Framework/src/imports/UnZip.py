#!/usr/bin/env python

import sys, base64, binascii, json, pathlib, os, gzip, zipfile
import regex as re
from imports.Signature import Signature, File_Check, Write_Binary_Payload, Write_Script_Payload


os.chdir(sys.path[0])

imports = pathlib.Path('imports').resolve()
outputs = pathlib.Path('outputs').resolve()
json_file = pathlib.Path('imports/Signatures.json').resolve()


################################################################################################################

def Unzip_File(Zip_File):
    print('\n   Attempting to unzip file...')
    Zip_File = pathlib.Path(f'outputs/{Zip_File}').resolve()
    
    try:
        with gzip.open(f'{Zip_File}', 'r') as r:
            File_Data = str(r.read())
        r.close()
        File_Data = File_Data.replace('\\n', '\n')
        File_Data = File_Data.replace('\\t', '\t')

        File_Found = File_Check(File_Data)
                    
        if File_Found:
            Write_Script_Payload(File_Found, File_Data)  
        
    except UnicodeDecodeError:
        print('A zipped binary file has been potentially detected. Unable to continue extraction. Manual extraction is needed.')
        
        ### In Progress Script section ###
        # Need more data on samples before writing contents


    return File_Data