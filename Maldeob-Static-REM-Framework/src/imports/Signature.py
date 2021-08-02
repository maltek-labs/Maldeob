#!/usr/bin/env python

import sys, binascii, json, pathlib, os
import regex as re

os.chdir(sys.path[0])

imports = pathlib.Path('imports').resolve()
outputs = pathlib.Path('outputs').resolve()
json_file = pathlib.Path('imports/Signatures.json').resolve()

###############################################################################################################
# Checks to see if payload/stage is JS or PS1 file.

def File_Check(Converted_Text):
    JS_Check1 = re.search(r"(?i)eval\(|ActiveXObject", Converted_Text, re.MULTILINE)
    JS_Check2 = re.search(r"(?i)\bvar\b\s\w{1,}", Converted_Text, re.MULTILINE)
    PS1_Check1 = re.search(r"(?i)New-Object|IEX|Invoke_Expression|Invoke-WebRequest|-enc|NET\.webclient", Converted_Text, re.MULTILINE)
    PS1_Check2 = re.search(r"(?i)\$\w{1,}|powershell", Converted_Text, re.MULTILINE)
    VBA_Check1 = re.search(r"(?i)\bDim\b", Converted_Text, re.MULTILINE)
    VBA_Check2 = re.search(r"(?i)\bSet\b|\bStep\b|\bEnd\sSub\b", Converted_Text, re.MULTILINE)
    XLM4_Check = re.search(r"(?i)(TBD)", Converted_Text, re.MULTILINE)
    

    if VBA_Check1 and VBA_Check2:
        File_Found = 'VBA_File'
        print(f'VBA code has been detected in file. Skipping VBA check.')
        print('')
        return File_Found
    
    elif JS_Check1 and JS_Check2:
        File_Found = 'JS'
        print(f'''\t
        \t\t|-------------------------------------------------------------------|
        \t\t\tA {File_Found} file has been detected. Attempting analysis...
        \t\t|-------------------------------------------------------------------|''')
        
        return  File_Found

    elif PS1_Check1 and PS1_Check2:
        File_Found = 'PS1'
        print(f'''\t
        \t\t|-------------------------------------------------------------------|
        \t\t\tA {File_Found} file has been detected. Attempting analysis...
        \t\t|-------------------------------------------------------------------|\n''')
        
        return File_Found
    
    else:
        return False
    
###############################################################################################################
# Checks Magic Byte value against signature list defined in Signatures.json.

def Signature(Magic_Byte):
    with open(f'{json_file}', 'r') as data:
            data = json.load(data)

    while not list(filter(lambda x:x["hex"] == Magic_Byte, data)):
        if not list(filter(lambda x:x["hex"] == Magic_Byte, data)):
            Magic_Byte = Magic_Byte[:-3]
            if len(Magic_Byte) <= 0:
                break
        else:
            pass
    
    if list(filter(lambda x:x["hex"] == Magic_Byte, data)):
        File_Found = list(filter(lambda x:x["hex"] == Magic_Byte, data))[0]['file_extension']
        File_Found = File_Found.upper()
        
        print('\nSignature(s) matched: \n'+ str(list(filter(lambda x:x["hex"] == Magic_Byte, data))[0]))
        print(f'\nA {File_Found} file has been found in the file. ')
        
        return File_Found
    else:
        return False
###############################################################################################################


def Write_Script_Payload(File_Found, File_Data):
    Stage_Calc = []
    
    for item in os.listdir(outputs):
        if re.search(r'Payload_Stage\d_.*\.file', item):
            Stage = re.search(rf'Payload_Stage(\d)_.*\.file', item).group(1)
            Stage_Calc.append(int(Stage))

     
    if Stage_Calc:
        Stage = max(Stage_Calc)
        Stage += 1
        
        with open(rf"{outputs}/Payload_Stage{Stage}_{File_Found}.file", 'w') as payload:
            payload.write(File_Data)
        print(f'The file has been saved as: Payload_Stage{Stage}_{File_Found}.file')
    
    else:
        Stage = 2
        with open(rf"{outputs}/Payload_Stage{Stage}_{File_Found}.file", 'w') as payload:
            payload.write(File_Data)
        print(f'The file has been saved as: Payload_Stage{Stage}_{File_Found}.file')
        
        Stage_Calc.clear()

###############################################################################################################

def Write_Binary_Payload(File_Found, File_Data):
    Stage_Calc = []
    
    for item in os.listdir(outputs):
        if re.search(r'Payload_Stage\d_.*\.file', item):
            Stage = re.search(rf'Payload_Stage(\d)_.*\.file', item).group(1)
            Stage_Calc.append(int(Stage))


    if Stage_Calc:
        Stage = max(Stage_Calc)
        Stage += 1
        
        with open(rf"{outputs}/Payload_Stage{Stage}_{File_Found}.file", 'wb') as payload:
            payload.write(File_Data)
        print(f'The file has been saved as: Payload_Stage{Stage}_{File_Found}.file')
    
    else:
        Stage = 2
        with open(rf"{outputs}/Payload_Stage{Stage}_{File_Found}.file", 'wb') as payload:
            payload.write(File_Data)
        print(f'The file has been saved as: Payload_Stage{Stage}_{File_Found}.file')

    Stage_Calc.clear()