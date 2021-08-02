#!/usr/bin/env python

import sys, base64, binascii, pathlib, os, json
import regex as re
from imports.Signature import Signature, File_Check, Write_Binary_Payload, Write_Script_Payload


os.chdir(sys.path[0])

imports = pathlib.Path('imports').resolve()
outputs = pathlib.Path('outputs').resolve()
ASCII_file = pathlib.Path('imports/ASCII.json').resolve()

################################################################################################################

def Cleanup_PS(PS_Code):
    
    # Cleans up code. More to come. 
    PS_Code = PS_Code.replace(';', ';\n')
    PS_Code = PS_Code.replace('`', '')
    PS_Code = re.sub(r'\'(?:[\(\)+ ]{1,})\'|\"(?:[\(\)+ ]{1,})\"', '', PS_Code)
    
    if re.search(r'(?i)\[char\](?:\d{1,3}|\(\d{1,3}\))', PS_Code):
        Char_list = re.findall(r'(?i)\[char\](?:\d{1,3}|\(\d{1,3}\))', PS_Code)
        print('\n\nFound [Char] being used. Attempting to replace with ASCII value...\n') 
        with open(ASCII_file, 'r') as data:
            data = json.load(data)

        for item in Char_list:
            ASCII_Digit = re.search(r'(\d{1,3})', item).group(1)

            for value in list(filter(lambda x:x["code"] == ASCII_Digit, data)):
                ASCII_Value = list(filter(lambda x:x["code"] == ASCII_Digit, data))[0]['ascii']
                print(f'Found {item}. Attempting to replace with {ASCII_Value}')
                PS_Code = re.sub(re.escape(item), f"\'{ASCII_Value}\'", PS_Code)
    
    
    return PS_Code

################################################################################################################

def PowerShell_File(PS_Code):
    try:
        PS_Code = Cleanup_PS(PS_Code)

        if re.search(r'(\"[0-9a-fA-F]{2,})\"|\'([0-9a-fA-F]{2,})\'', PS_Code, re.MULTILINE):
            print('\n\t\t\t####################################################################')
            PS_Code = Hex_Encoded_Paylod(PS_Code)
        
        if re.search(r'function[\s\S]*}|\$\b\w{1,}\b', PS_Code, re.MULTILINE):
            print('\n\t\t\t####################################################################')
            PS_Code = Replace_Single_Init(PS_Code)
            
        if re.search(r'((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/][AQgw]==|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=)?)', PS_Code, re.MULTILINE):
            print('\n\t\t\t####################################################################')
            PS_Code = Base64_Decode_PS1(PS_Code)



        if PS_Code:         

            if '\x00' in PS_Code:
                PS_Code = PS_Code.replace('\x00', '')

            PS_Code = Cleanup_PS(PS_Code)
            
            if re.search(r'(\"[0-9a-fA-F]{2,})\"|\'([0-9a-fA-F]{2,})\'', PS_Code, re.MULTILINE):
                print('\n\t\t\t####################################################################')
                PS_Code = Hex_Encoded_Paylod(PS_Code)
        
            if re.search(r'function[\s\S]*}|\$\b\w{1,}\b', PS_Code, re.MULTILINE):
                print('\n\t\t\t####################################################################')
                PS_Code = Replace_Single_Init(PS_Code)

            with open(f"{outputs}/Payload_PS1.file", 'w', encoding='utf-8') as payload:
                payload.write(PS_Code)
            payload.close()
            
            print('\nCompleted analysis.')
            print(f'\n\nCleaned up and/or deobfuscated code has been written to {outputs} as Payload_PS1.file.\n')
    except:
            print('There was an error that has occurred during deobfuscation.')
            print('Manual investigation & deobfuscation will be needed.\n')

################################################################################################################

def Base64_Decode_PS1(PS_Code):
    Original_PS_Code = PS_Code
    
    try:
        
        print('\nAttempting to check for Base64 encoded data...\n')
        
        Base64_Search = re.findall(r'((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/][AQgw]==|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=)?)', PS_Code, re.MULTILINE)
    
        if Base64_Search:
            for item in Base64_Search:
                
                if len(item) <= 18:
                    pass
                
                elif len(item) >= 19 and len(item) <= 122:
                    try:
                        
                        Decoded_Data = base64.decodebytes(bytearray(item, 'utf-8')).decode('utf-8')
                        if '\x00' in Decoded_Data:
                            pass
                        else:
                            print('Base64 encoded data found. Replacing data with:\n ')
                            print(f'{Decoded_Data}')
                            VBA = VBA.replace(item, Decoded_Data)
                    
                    except UnicodeDecodeError:
                        pass
                
                elif len(item) >= 123:          
                    try:
                        
                        # Attempts to decode Base64 encoded data that have been encoded with UTF-8 that may contain additonal payloads or stages. (PowerShell, JavaScript, etc). 
                        # If file is binary a UniDecodeError occurs and handling of binary file is executed.
                        File_Data = base64.decodebytes(bytearray(item, 'utf-8')).decode('utf-8')

                        #checks to see if Script Matches Regex values by calling File_Check in Signatures.py then writes to outputs folder if it exists. 
                        File_Found = File_Check(File_Data)
                        
                        if File_Found:
                            print('Base64 encoded script found.\n')
                            Write_Script_Payload(File_Found, File_Data)
                        if len(item) >= 300:
                            pass
                        
                            

                    except UnicodeDecodeError:
                        
                        # If malware has a Base64 file encoded (PE file for example) the decoding throws a UnicodeDecodeError exception and the file is decoded. 
                        File_Data = base64.decodebytes(bytearray(item, 'ascii'))
                        
                        Magic_Byte = str(binascii.hexlify(binascii.a2b_base64(item))).replace('b\'', '').replace('\'', '').upper()
                        

                        # Builds the Magic Byte value from the decoded bytes after conversion to the proper starting length.
                        while len(Magic_Byte) >= 13:
                            Magic_Byte = str(Magic_Byte)[:-1]
                        
                        Magic_Byte = (' '.join(Magic_Byte[i:i+2] for i in range(0,len(Magic_Byte),2)))
                        
                        # Checks to see if Magic Byte value exists by calling Signature from Signatures.py then writes to outputs folder if it exists. 
                        File_Found = Signature(Magic_Byte)
                        
                        if File_Found:
                            if len(item) >= 1000:
                            
                                print('\nBase64 encoded payload has been detected. Writing payload.')
                                Write_Binary_Payload(File_Found, File_Data)
                            else:
                                print('\nCould not save file. Incomplete PE file found. PE may be segmented in code.')
    except:         
        PS_Code = Original_PS_Code
        print('There was an error during deobfuscating Base64 content. Restoring Powershell code and continuing analysis.')
    
    return PS_Code
################################################################################################################

def Hex_Encoded_Paylod(PS_Code):
    Original_PS_Code = PS_Code
    
    try: 
        # Variable Setup    
        Stage_Calc = []
        
        Hex_Regex1 = r'\"([0-9a-fA-F]{2,})\"'
        Hex_Regex2 = r'\'([0-9a-fA-F]{2,})\''
        
        # Pulls all Hex values found in code
        if re.search(Hex_Regex1, PS_Code, re.MULTILINE):
            Hex_List = re.findall(Hex_Regex1, PS_Code)
        elif re.search(Hex_Regex2, PS_Code, re.MULTILINE):
            Hex_List = re.findall(Hex_Regex2, PS_Code)

        for item in Hex_List:
            # Sets up the magic byte value
            Magic_Byte = item[:24]
            
            # Formats the hex into proper format for parsing
            Magic_Byte = (' '.join(Magic_Byte[i:i+2] for i in range(0,len(Magic_Byte),2)))
            File_Data = binascii.unhexlify(item)

            # Checks for any known signatures and outputs data if found. 
            File_Found = Signature(Magic_Byte)

            if File_Found:
                print('\nHEX obfuscated payload has been detected. Writing payload.')
                Write_Binary_Payload(File_Found, File_Data)
    except:
        PS_Code = Original_PS_Code
        print('There was an error during deobfuscating HEX content. Restoring Powershell code and continuing analysis.')
    return PS_Code

################################################################################################################

def Replace_Single_Init(PS_Code):
    Original_PS_Code = PS_Code
    
    PS_Defined_Var = ['$$', '$?', '$^', '$args', '$ConsoleFileName', '$Error', '$Event', '$EventArgs', '$EventSubscriber', '$ExecutionContext', '$false', '$foreach', '$HOME', '$Host', '$input', '$IsCoreCLR', '$IsLinux', '$IsMacOS', '$IsWindows', '$LastExitCode', '$Matches', '$MyInvocation', '$NestedPromptLevel', '$null', '$PID', '$PROFILE', '$PSBoundParameters', '$PSCmdlet', '$PSCommandPath', '$PSCulture', '$PSDebugContext', '$PSHOME', '$PSItem', '$PSScriptRoot', '$PSSenderInfo', '$PSUICulture', '$PSVersionTable', '$PWD', '$Sender', '$ShellId', '$StackTrace', '$switch', '$this', '$true', '$ErrorActionPreference']

    try:
        VarName_List = re.findall(r'\$\b\w{1,}\b', PS_Code)
        
        Var_regex = r'\$\b\w{1,}\b'
        
        if VarName_List:
            Tally_Count = 0
            
            print('\n\nNow checking for single initialized variables.')
            print(f'Total Amount of variables to check: {len(VarName_List)}\n\tPlease wait...\n')
            
            for item in VarName_List:
                
                if item not in PS_Defined_Var:
                    VarName = re.search(r'(?i)\$\b(\w{1,})\b', item).group(1)
                    
                    Matches_Num = 0
                    for match in re.finditer(rf'(?i)\${VarName}', PS_Code):    
                        Matches_Num += 1

                    if Matches_Num == 1:
                        if re.search(rf'(?i)(\${VarName}(?:= | =|=| = )).*;', PS_Code, re.MULTILINE):
                            PS_Code = re.sub(rf'(?i)(\${VarName}(?:= | =|=| = )).*;', '', PS_Code, count=1)
                            Tally_Count += 1
                            print(f'Detected \'${VarName}\' being only intialized once. Removing...')
                        else:
                            PS_Code = re.sub(rf'(?i)\${VarName}', '', PS_Code, count=1)
                            Tally_Count += 1
                            print(f'Detected \'${VarName}\' being only intialized once. Removing...')

            if Tally_Count == 0:
                print('\nNo variables were replaced. Each variable is being referenced in the code.\n')
            else:
                print(f'''
                        |-------------------------------------------------------------------|
                        Completed. The total amount of Variables that were removed is: {Tally_Count} 
                        |-------------------------------------------------------------------|''')
        
        return PS_Code
    
    except:
        PS_Code = Original_PS_Code
        print('There was an error when replacing single initialized variables. Restoring Powershell code and continuing analysis.')

        return PS_Code
            