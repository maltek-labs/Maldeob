#!/usr/bin/env python

import sys, base64, binascii, json, pathlib, os
import regex as re
from imports.Signature import Signature, File_Check, Write_Binary_Payload, Write_Script_Payload
from oletools.olevba import VBA_Parser

os.chdir(sys.path[0])

imports = pathlib.Path('imports').resolve()
outputs = pathlib.Path('outputs').resolve()
ASCII_file = pathlib.Path('imports/ASCII.json').resolve()

################################################################################################################
def Check_VBA(ifile):
    vbaparser = VBA_Parser(ifile)
    
    ifile_Name = re.search(r'[\/\\](\w{1,}\.\w{1,})|[\/\\](\w{1,})$', ifile, re.IGNORECASE).group(1)
    if ifile_Name:
        pass
    else:
        ifile_Name = re.search(r'[\/\\](\w{1,}\.\w{1,})|[\/\\](\w{1,})$', ifile, re.IGNORECASE).group(2)

    if vbaparser.detect_vba_macros():
        
        print(f'''\t
        \t\t|-------------------------------------------------------------------|
        \t\t\tVBA Macros have been found in {ifile_Name}.
        \n\t\t\t\tAttempting to pull macros... 
        \t\t|-------------------------------------------------------------------|
        ''')

        results = vbaparser.analyze_macros(show_decoded_strings=True, deobfuscate=True)
        
        # for kw_type, keyword, description in results: 
        #    Results_List.append('type: %s | keyword: %s' % (kw_type, keyword) + '\n')
        
        VBA = vbaparser.reveal()

        with open(f"{outputs}/Payload_VBA.file", 'w', errors='ignore') as payload:
            payload.write(VBA)
        payload.close()

        print(f'Pull successful. Original File VBA Code has been saved to {outputs} as Payload_VBA.file.')
    else:
        print(f'VBA Macros have not been found in {ifile}.\n')
        VBA = False
    return VBA

################################################################################################################

def Code_CleanUp(VBA):
    # General code cleanup. concats strings together in case either direct VBA file is inputted or missed during VBA check. 
    # More to come as methods are found.
    
    if re.search(r'((?:\"(?:&| & | &|& )\")|(?:\'(?:&| & | &|& )\'))', VBA, re.MULTILINE):
        VBA = re.sub(r'((?:\"(?:&| & | &|& )\")|(?:\'(?:&| & | &|& )\'))', '', VBA)
    
    if re.search(r'(?i)\([\"\']MSScriptControl\.ScriptControl[\"\']\)\.Language[ =]{1,3}[\"\']JScript[\"\']', VBA, re.MULTILINE):
        VBA = re.sub(r';', ';\n', VBA)

    return VBA

################################################################################################################

def VBA_File(VBA):
    
    if VBA:
        try: 
            
            ################################
            
            print('\n\t\t\t####################################################################')
            VBA = VBA_Var_Replace(VBA)
            
            if re.search(r'ChrW\(\d{1,3}\)|Chr\(\d{1,3}\)', VBA, re.MULTILINE):
                print('\n\t\t\t####################################################################')
                VBA = VBA_ChrW_Replace(VBA)
                
            if re.search(r'\"([0-9a-fA-F]{2,})\"|\'([0-9a-fA-F]{2,})\'', VBA, re.MULTILINE):
                print('\n\t\t\t####################################################################')
                VBA = VBA_HEX_Deobfuscation(VBA)

            VBA = Code_CleanUp(VBA)

            if re.search(r'((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/][AQgw]==|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=)?)', VBA, re.MULTILINE):
                print('\n\t\t\t####################################################################')
                VBA = Base64_Decode_VBA(VBA)
            
            ################################
            
            VBA = Code_CleanUp(VBA)

            if VBA:
                with open(f"{outputs}/Payload_Deobfuscated_VBA.file", 'w', encoding='utf-8') as payload:
                    payload.write(VBA)
                payload.close()
                print(f'\nDeobfuscated VBA Code has been saved to {outputs} as Payload_Deobfuscated_VBA.file.\n')
        except:
            print('There was an error that has occurred during deobfuscation. Original VBA code has been restored.\n')
            print('Manual investigation & deobfuscation will be needed.\n')

################################################################################################################
def VBA_Var_Replace(VBA):
    
    try: 
        # Comment clean up if there is any. 
        if re.search(r'^\s{1,}\'.*\n', VBA, re.MULTILINE):
            VBA = re.sub(r'^\s{1,}\'.*\n', '', VBA)
        
        # Attempts to replace potential Hex values found in code. Stored backup of original code in Original_VBA.
        Original_VBA = VBA

        Tally_Count = 0

        VarName_List = re.findall(r'\s(\b[\w]{1,}\b)\sAs', VBA, re.MULTILINE)
        Dim_VarName_List = re.findall(r'Dim\s(\b[\w]{1,}\b)\s', VBA, re.MULTILINE)
        Set_VarName_List = re.findall(r'Set\s(\b[\w]{1,}\b)\s', VBA, re.MULTILINE)
        Not_Completed_VarName_List = []

        for item in Dim_VarName_List:
            if item not in VarName_List:
                VarName_List.append(item)

        for item in Set_VarName_List:
            if item not in VarName_List:
                VarName_List.append(item)
        
        
        print(f'Total Amount of variables to replace is: {len(VarName_List)}')
        print('Attempting to replace variables with contents. \n\tPlease wait...\n\n')

        for item in VarName_List:       
            
            Matches_Num = 0
            for match in re.finditer(rf'\b{item}\b\s=\s', VBA):
                Matches_Num += 1
            
            if Matches_Num == 0:
                VBA = re.sub(rf'Dim\s\b{item}\b', '', VBA, count=1)
                Tally_Count += 1
                print(f'Completed {Tally_Count} out of {len(VarName_List)}')
            
            if Matches_Num == 1:
                # Removes Dim Variable
                VBA = re.sub(rf'Dim\s\b{item}\b.*\n', '', VBA, count=1)

                # Pulls, removes, & replaces Variable with contents found
                VarContents = re.search(rf'\b{item}\b\s=\s(.*?)\n', VBA).group(1)
                VBA = re.sub(rf'\b{item}\b\s=\s.*\n', '', VBA, count=1)
                VBA = re.sub(rf'\b{item}\b', VarContents, VBA)

                Tally_Count += 1
                print(f'Completed {Tally_Count} out of {len(VarName_List)}')

            if Matches_Num >= 2:
                if re.search(rf'\b{item}\b\s=\s.*\b{item}\b.*\n', VBA , re.MULTILINE):
                    # Removes Dim Variable
                    VBA = re.sub(rf'Dim\s\b{item}\b.*\n', '', VBA, count=1)

                    # Pulls, removes, & sets up Variable Contents for replacement
                    VarContents = re.search(rf'\b{item}\b\s=\s(.*?)\n', VBA).group(1)
                    VBA = re.sub(rf'\b{item}\b\s=\s.*\n', '', VBA, count=1)
                    
                    VBA = re.sub(rf'\b{item}\b', rf'Var_{item}', VBA, count=1)
                    VBA = re.sub(rf'\b{item}\b', rf'{VarContents}', VBA, count=1)
                    VarContents = re.search(rf'\bVar_{item}\b\s=\s(.*?)\n', VBA).group(1)

                    if not re.search(rf"\b{item}\b\s=\s(.*?)$", VBA, re.MULTILINE):
                        VBA = re.sub(rf'\bVar_{item}\b\s=\s.*\n', '', VBA, count=1)
                        VBA = re.sub(rf'\b{item}\b', VarContents, VBA)
                        Tally_Count += 1
                        print(f'Completed {Tally_Count} out of {len(VarName_List)}')
                    
                    elif re.search(rf"\bVar_{item}\b\s=\s.*?$", VBA, re.MULTILINE):
                        if not re.search(rf"\b{item}\b\s=\s(.*?)$", VBA, re.MULTILINE):
                            VBA = re.sub(rf'\b{item}\b', VarContents, VBA)
                            Tally_Count += 1
                            print(f'Completed {Tally_Count} out of {len(VarName_List)}')
                    
                        else:
                        # Loops through VBA code and replaces all variables being reassigned to itself
                            while VBA.count(item) >= 3:
                                
                                VarContents = re.search(rf'\bVar_{item}\b\s=\s(.*?)\n', VBA).group(1)
                                VBA = re.sub(rf'\bVar_{item}\b\s=\s.*\n', '', VBA, count=1)
                                
                                VBA = re.sub(rf'\b{item}\b', rf'Var_{item}', VBA, count=1)
                                VBA = re.sub(rf'\b{item}\b', rf'{VarContents}', VBA, count=1)
                                
                                if VBA.count(item) == 2:
                                    break

                            # Final assignment & replacement of variable contents
                            VarContents = re.search(rf'\bVar_{item}\b\s=\s(.*?)\n', VBA).group(1)
                            VBA = re.sub(rf'\bVar_{item}\b\s=\s.*\n', '', VBA, count=1)
                            VBA = re.sub(rf'\b{item}\b', rf'{VarContents}', VBA, count=1)
                            Tally_Count += 1
                            print(f'Completed {Tally_Count} out of {len(VarName_List)}')

                else:
                    Not_Completed_VarName_List.append(item)
                    
                    # In progress Code: 

                        # while VBA.count(item) >= 3:
                        #     if re.search(rf'\b{item}\b\s=\s.*\n', VBA , re.MULTILINE):
                                
                        #         if re.search(rf'Dim\s\b{item}\b\sAs\s\w{1,}', VBA , re.MULTILINE):
                        #             VBA = re.sub(rf'Dim\s\b{item}\b\sAs\s\w{1,}\n', '', VBA, count=1)
                                    
                        #         elif re.search(rf'Dim\s\b{item}\b\sAs\s\w{1,},', VBA , re.MULTILINE):
                        #             VBA = re.sub(rf'Dim\s\b{item}\b\sAs\s\w{1,},', '', VBA, count=1)
                                
                        #         elif re.search(rf'Dim\s\b{item}\b\n', VBA , re.MULTILINE):
                        #             VBA = re.sub(rf'Dim\s\b{item}\b\n', '', VBA, count=1)
                                
                        #         elif re.search(rf'Dim\s\b{item}\b,', VBA , re.MULTILINE):
                        #             VBA = re.sub(rf'Dim\s\b{item}\b,', '', VBA, count=1)
                                
                        #         elif re.search(rf',\s\b{item}\b\sAs\sObject\n', VBA , re.MULTILINE):
                        #             VBA = re.sub(rf',\s\b{item}\b\sAs\sObject\n', '', VBA, count=1)
                                
                        #         # Removes Variable assignment
                        #         VBA = re.sub(rf'\s\b{item}\b\sAs\s\w{1,},|\s\b{item}\b[,\n]', '', VBA, count=1)
                        #         # print(VBA)

                        #         # Pulls & removes Contents of Variable
                        #         VarContents = re.search(rf'\b{item}\b\s=\s(.*?)\n', VBA).group(1)
                        #         VBA = re.sub(rf'\b{item}\b\s=\s.*\n', '', VBA, count=1)
                                
                                

                        #         if not re.search(rf'\b{item}\b\s=\s.*\n', VBA , re.MULTILINE):
                        #             # Replaces next Variable with contents
                        #             VBA = re.sub(rf'\b{item}\b', rf'{VarContents}', VBA)
                        #         elif re.search(rf'\b{item}\b\s=\s.*\n', VBA , re.MULTILINE):
                        #             VBA = re.sub(rf'\b{item}\b', rf'{VarContents}', VBA, count=1)
                        #     else:
                        #         break
        
        VarName_List.clear()


        if Not_Completed_VarName_List:
            print('Not all variables have been completed. Some manual work may be required.\n')
            print(f'\nThe variables that have not been completed are: {Not_Completed_VarName_List}')
        else:
            VBA = VBA.replace('Set', '')
            VBA = re.sub(r'^\s{2,}\bAs\s\w{1,}\b', '', VBA)
    
    except:
        # If errors occurs old VBA Code is restored then returned. 
        print('There was an error when replacing Variables with contents. Restoring VBA code and continuing analysis.')
        VBA = Original_VBA
    
    return VBA

################################################################################################################
def VBA_ChrW_Replace(VBA):
    try: 
    # Attempts to replace potential Hex values found in code. Stored backup of original code in Original_VBA.
        Original_VBA = VBA


        print('Attempting to decode & replace Chr/ChrW with ASCII characters. \n\tPlease wait...\n\n')

        ChrW_Regex = r'(ChrW?\(\d{1,3}\))'
        ChrW_Contents_Regex = r'ChrW?\((\d{1,3})\)'

        ChrW = re.findall(ChrW_Regex, VBA)

        with open(ASCII_file, 'r') as data:
            data = json.load(data)

        for item in ChrW:
            Char_Contents = re.search(ChrW_Contents_Regex, item).group(1)
            for value in list(filter(lambda x:x["code"] == Char_Contents, data)):
                ASCII_Value = list(filter(lambda x:x["code"] == Char_Contents, data))[0]['ascii']
                VBA = re.sub(rf'(ChrW?\({Char_Contents}\))', f"\'{ASCII_Value}\'", VBA)

            VBA = re.sub(r'(\s&\s)', '', VBA)
            VBA = re.sub(r'(\'\')', '', VBA)
        
        print('Completed Chr/ChW decode.\n')
    
    except:
        # If errors occurs old VBA Code is restored then returned. 
        VBA = Original_VBA
        print('There was an error during deobfuscating Chr/ChrW content. Restoring VBA code and continuing analysis.')
    
    return VBA

################################################################################################################

def VBA_HEX_Deobfuscation(VBA):
    try: 
        # Attempts to replace potential Hex values found in code & stores backup of original code in Original_VBA.
        Original_VBA = VBA
        
        
        print('\nAttempting to check for HEX encoded data. \n\tPlease wait...\n\n')

        VBA_Hex_Regex = r'\"([0-9a-fA-F]{2,})\"|\'([0-9a-fA-F]{2,})\''
        Hex_Functon_Regex = r'(\w{1,}\(\"[0-9a-fA-F]{2,}\"\)|\(\'[0-9a-fA-F]{2,}\'\))'
        Find_Hex_Functions = re.findall(Hex_Functon_Regex, VBA)
        

        for item in Find_Hex_Functions:
            
            Hex_Value = re.search(VBA_Hex_Regex, item).group(1)
            ascii_Chr = str(binascii.unhexlify(Hex_Value)).replace('b', '').replace('\'', '\"')
            
            
            Full_Function = rf'{item}'.replace(')', '\)').replace('(', '\(').replace('"', '\\"')
            Full_Function = rf'({Full_Function})'
            
            VBA = re.sub(Full_Function, ascii_Chr, VBA)
            VBA = re.sub(r'(\"\s&\s\"|\'\s&\s\')', '', VBA)
        
        print('\nCompleted decoding HEX data. ')
    
        #######################################################################################

        # Variable Setup    
        Stage_Calc = []
        
        Hex_Regex1 = r'\"([0-9a-fA-F]{2,})\"'
        Hex_Regex2 = r'\'([0-9a-fA-F]{2,})\''
        
        # Pulls all Hex values found in code
        if re.search(Hex_Regex1, VBA, re.MULTILINE):
            Hex_List = re.findall(Hex_Regex1, VBA)
        elif re.search(Hex_Regex2, VBA, re.MULTILINE):
            Hex_List = re.findall(Hex_Regex2, VBA)

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
        # If errors occurs old VBA Code is restored then returned. 
        VBA = Original_VBA
        print('No HEX Content found. Continuing analysis.\n')
    
    return VBA 

################################################################################################################

def Base64_Decode_VBA(VBA):
    Original_VBA = VBA
    
    try:
        print('\nAttempting to check for Base64 encoded data...\n')
        
        Base64_Search = re.findall(r'((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/][AQgw]==|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=)?)', VBA, re.MULTILINE)
    
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
        VBA = Original_VBA
        print('There was an error during deobfuscating Base64 content. Restoring VBA code and continuing analysis.')
                    
    return VBA