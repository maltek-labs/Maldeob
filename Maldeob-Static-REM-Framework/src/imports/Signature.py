#!/usr/bin/env python

import sys, argparse, re, jsbeautifier, base64, binascii, json, pathlib, os

os.chdir(sys.path[0])

imports = pathlib.Path('imports').resolve()
outputs = pathlib.Path('outputs').resolve()
json_file = pathlib.Path('imports/Signatures.json').resolve()




###############################################################################################################
# Checks to see if payload/stage is JS or PS1 file.

def File_Check(Converted_Text):
    JS_Check = re.search(r"(?i)(eval)", Converted_Text, re.MULTILINE)
    PS1_Check = re.search(r"(?i)(New-Object|Invoke-Webrequest|)", Converted_Text, re.MULTILINE)
    VBA_Check = re.search(r"(?i)(Dim|Set|Step|Chrw\(|Chr\()", Converted_Text, re.MULTILINE)
    Excel4_Check = re.search(r"(?i)(TBD)", Converted_Text, re.MULTILINE)
    

    if re.search(r"(?i)(eval)", Converted_Text, re.MULTILINE):
        File_Found = 'JS'
        print('A ' + f'{File_Found}' + ' file has been detected')
        print('')
        return  File_Found

    elif re.search(r"(?i)(New-Object|Invoke-Webrequest)", Converted_Text, re.MULTILINE):
        File_Found = 'PS1'
        print('A ' + f'{File_Found}' + ' file has been detected')
        print('')
        return File_Found

    elif re.search(r"(?i)(Dim|Set|Step|Chrw\(|Chr\()", Converted_Text, re.MULTILINE):
        File_Found = 'VBA_File'
        print(f'VBA code has been detected in file. Skipping VBA check.')
        print('')
        return File_Found
    else:
        return False
    
###############################################################################################################
# Checks Magic Byte value against signature list defined in Signatures.json.

def Signature(Signature_Check):
    with open(f'{json_file}', 'r') as data:
            data = json.load(data)

    while not list(filter(lambda x:x["hex"] == Signature_Check, data)):
        if not list(filter(lambda x:x["hex"] == Signature_Check, data)):
            Signature_Check = Signature_Check[:-3]
            if len(Signature_Check) <= 0:
                break
        else:
            pass
    
    if list(filter(lambda x:x["hex"] == Signature_Check, data)):
        File_Found = list(filter(lambda x:x["hex"] == Signature_Check, data))[0]['file_extension']
        
        print('Signature(s) matched: \n'+ str(list(filter(lambda x:x["hex"] == Signature_Check, data))[0]))
        
        return File_Found
    else:
        return False
###############################################################################################################