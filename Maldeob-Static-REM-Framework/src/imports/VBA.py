#!/usr/bin/env python

import sys, base64, binascii, json, pathlib, os, shutil
import regex as re
from imports.Signature import Signature, File_Check
from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML

os.chdir(sys.path[0])

imports = pathlib.Path('imports').resolve()
outputs = pathlib.Path('outputs').resolve()
json_file = pathlib.Path('imports/Signatures.json').resolve()
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
        print(f'''
        ################################################################
         VBA Macros have been found in {ifile_Name}.                       
        ################################################################\n
        
        Attempting to pull macros... 
         ''')

        results = vbaparser.analyze_macros(show_decoded_strings=True, deobfuscate=True)
        
        # for kw_type, keyword, description in results: 
        #    Results_List.append('type: %s | keyword: %s' % (kw_type, keyword) + '\n')
        
        VBA = vbaparser.reveal()
        
        
        with open(f"{outputs}/Payload_VBA.file", 'w', errors='ignore') as payload:
            payload.write(VBA)
        payload.close()

        print(f'Pull successful. Original File VBA Code has been saved to {outputs} as Payload_VBA.file.\n')
    else:
        print(f'VBA Macros have not been found in {ifile}.\n')
        VBA = False
    return VBA
################################################################################################################

def Single_Init_Var(VBA):
    VarName = re.findall(r'Dim\s\b([\w]{1,}\b)', VBA, re.MULTILINE)
    
    for item in VarName:
        if VarName.count(item) >= 2:
            VarName.remove(item)

    i = 0
    while i < len(VarName):
        regex = rf"Dim\s{VarName[i]}.*?[\n$]"
        if VBA.count(VarName[i]) == 2:        
            text_after = re.sub(regex, '', VBA, flags=re.MULTILINE)
            VBA = text_after
            
        i += 1
    return VBA


################################################################################################################
def VBA_Var_Replace(VBA):
    
    VarName = re.findall(r'Dim\s\b([\w]{1,}\b)', VBA, re.MULTILINE)
    for Var in VarName:       

        if re.search(rf'Dim\s(\b{Var}\b)', VBA, re.MULTILINE):
            VBA = re.sub(rf'(?i)\b({Var})\b\s', f'Var_{Var} ', VBA, count=1)
            
            while re.search(rf"\b{Var}\b\s=\s(.*?)$", VBA, re.MULTILINE):    
                
                if re.search(rf"\b{Var}\b\s=\s(.*?)$", VBA, re.MULTILINE):
                    VarContents = re.search(rf"\b{Var}\b\s=\s(.*?)$", VBA, re.MULTILINE).group(1)
                    VBA = re.sub(rf'(?i)\b({Var})\b\s', f'Var_{Var} ', VBA, count=1)
                    
                    
                    if re.search(rf"\b{Var}\b\s=\s.*\b{Var}\b", VBA, re.MULTILINE):
                        VBA = re.sub(rf'(?i)\b({Var})\b\s', f'Var__{Var} ', VBA, count=1)
                        
                        VBA = re.sub(rf'(?i)\b({Var})\b', VarContents, VBA, count=1)
                        VarContents = re.search(rf"Var__{Var}\s=\s(.*?)$", VBA, re.MULTILINE).group(1)
                        
                        if not re.search(rf"\b{Var}\b\s=\s(.*?)$", VBA, re.MULTILINE):
                            VBA = re.sub(rf'(?i)\b({Var})\b', VarContents, VBA)

                else:
                    VBA = re.sub(rf'(?i)\b({Var})\b\s', f'{VarContents}', VBA)
                    break
        
        if re.search(rf"\b{Var}\b\s=\s.*\b{Var}\b", VBA, re.MULTILINE):
            VBA = re.sub(rf'(?i)\b({Var})\b\s', f'Var_{Var} ', VBA, count=1)
            VBA = re.sub(rf'(?i)\b({Var})\b', VarContents, VBA, count=1)
            VarContents = re.search(rf"\bVar_{Var}\b\s=\s(.*?)$", VBA, re.MULTILINE).group(1)
           
            if not re.search(rf"\b{Var}\b\s=\s(.*?)$", VBA, re.MULTILINE):
                if not re.search(rf"\b{Var}\b\s=\s.*\b{Var}\b", VBA, re.MULTILINE):
                    VBA = re.sub(rf'(?i)\b({Var})\b', VarContents, VBA)
        else: 
            if not re.search(rf"\b{Var}\b\s=\s(.*?)$", VBA, re.MULTILINE):
               
                if VarContents:
                    VBA = re.sub(rf'(?i)\b({Var})\b', VarContents, VBA)
    VarName.clear()

    ######################################################################

    VarName = re.findall(r'Set\s\b([\w]{1,}\b)', VBA, re.MULTILINE)
    for Var in VarName:       
        if re.search(rf'Set\s(\b{Var}\b)', VBA, re.MULTILINE):
            VBA = re.sub(rf'(?i)\b({Var})\b\s', f'Var_{Var} ', VBA, count=1)
            
            while re.search(rf"\b{Var}\b\s=\s(.*?)$", VBA, re.MULTILINE):    
                
                if re.search(rf"\b{Var}\b\s=\s(.*?)$", VBA, re.MULTILINE):
                    VarContents = re.search(rf"\b{Var}\b\s=\s(.*?)$", VBA, re.MULTILINE).group(1)
                    VBA = re.sub(rf'(?i)\b({Var})\b\s', f'Var_{Var} ', VBA, count=1)
                    
                    
                    if re.search(rf"\b{Var}\b\s=\s.*\b{Var}\b", VBA, re.MULTILINE):
                        VBA = re.sub(rf'(?i)\b({Var})\b\s', f'Var__{Var} ', VBA, count=1)
                        
                        VBA = re.sub(rf'(?i)\b({Var})\b', VarContents, VBA, count=1)
                        VarContents = re.search(rf"Var__{Var}\s=\s(.*?)$", VBA, re.MULTILINE).group(1)
                        
                        if not re.search(rf"\b{Var}\b\s=\s(.*?)$", VBA, re.MULTILINE):
                            VBA = re.sub(rf'(?i)\b({Var})\b', VarContents, VBA)

                else:
                    VBA = re.sub(rf'(?i)\b({Var})\b\s', f'{VarContents}', VBA)
                    break
        
        if re.search(rf"\b{Var}\b\s=\s.*\b{Var}\b", VBA, re.MULTILINE):
            VBA = re.sub(rf'(?i)\b({Var})\b\s', f'Var_{Var} ', VBA, count=1)
            VBA = re.sub(rf'(?i)\b({Var})\b', VarContents, VBA, count=1)
            VarContents = re.search(rf"\bVar_{Var}\b\s=\s(.*?)$", VBA, re.MULTILINE).group(1)
           
            if not re.search(rf"\b{Var}\b\s=\s(.*?)$", VBA, re.MULTILINE):
                if not re.search(rf"\b{Var}\b\s=\s.*\b{Var}\b", VBA, re.MULTILINE):
                    VBA = re.sub(rf'(?i)\b({Var})\b', VarContents, VBA)
        else: 
            if not re.search(rf"\b{Var}\b\s=\s(.*?)$", VBA, re.MULTILINE):
               
                if VarContents:
                    VBA = re.sub(rf'(?i)\b({Var})\b', VarContents, VBA)
    
    VarName.clear()
    
    Var_Name_Regex = r'(\b\w{1,}\b)\s=\s\".*?\"|(\b\w{1,}\b)\s=\s\'.*?\''
    Var_List = re.findall(Var_Name_Regex, VBA)

    for item in Var_List:
        if re.search(rf'\b{item}\b\s=\s\".*?\"', item):
        
            Var_String = rf'\b{item}\b\s=\s(\".*?\")'.group(1)
            VBA = re.sub(item, f'Var_{item}', count=1)
            VBA = re.sub(item, Var_String, count=1)
        elif re.search(r'(\b\w{1,}\b)\s=\s\'.*?\'', item):
            Var_String = rf'\b{item}\b\s=\s(\'.*?\')'.group(1)
            VBA = re.sub(item, f'Var_{item}', count=1)
            VBA = re.sub(item, Var_String, count=1)

    VBA = VBA.replace('" + "', '').replace("' + '", '').replace(' + ', '')
    VBA = VBA.replace('Var_', '').replace('Var__', '')
    
    return VBA

################################################################################################################
def VBA_ChrW_Replace(VBA):
    ChrW_Regex = r'(ChrW\(\d{1,3}\)|Chr\(\d{1,3}\))'
    ChrW_Contents_Regex = r'ChrW\((\d{1,3})\)|Chr\((\d{1,3})\)'

    ChrW = re.findall(ChrW_Regex, VBA)
    
    with open(ASCII_file, 'r') as data:
        data = json.load(data)


    for item in ChrW:
        Char_Contents = re.search(ChrW_Contents_Regex, item).group(1)
        for value in list(filter(lambda x:x["code"] == Char_Contents, data)):
            ASCII_Value = list(filter(lambda x:x["code"] == Char_Contents, data))[0]['ascii']
            VBA = re.sub(rf'(ChrW\({Char_Contents}\))', f"'{ASCII_Value}'", VBA)

        VBA = re.sub(r'(\s&\s)', '', VBA)
        VBA = re.sub(r'(\'\')', '', VBA)
    
    return VBA

################################################################################################################

def VBA_HEX_Replace(VBA):
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

    return VBA


def String_Replace(VBA):
    
    Var_Name_Regex = r'(\b\w{1,}\b)\s=\s\".*?\"'
    Var_List = re.findall(Var_Name_Regex, VBA)
    for item in Var_List:
        Var_String = re.search(rf'\b{item}\b\s=\s(\".*?\")', VBA, re.MULTILINE).group(1)
        VBA = re.sub(rf'\b{item}\b', f'Var_{item}', VBA, count=1)
        VBA = re.sub(rf'\b{item}\b', Var_String, VBA, count=1)   
    Var_List.clear()

    
    Var_Name_Regex = r'(\b\w{1,}\b)\s=\s\'.*?\''
    Var_List = re.findall(Var_Name_Regex, VBA)
    for item in Var_List:
        Var_String = re.search(rf'\b{item}\b\s=\s(\'.*?\')', VBA, re.MULTILINE).group(1)
        VBA = re.sub(rf'\b{item}\b', f'Var_{item}', VBA, count=1)
        VBA = re.sub(rf'\b{item}\b', Var_String, VBA, count=1)   
    Var_List.clear()


    VBA = VBA.replace('" + "', '').replace("' + '", '').replace(' + ', '')
    VBA = VBA.replace('Var_', '').replace('Var__', '')
    
    return VBA