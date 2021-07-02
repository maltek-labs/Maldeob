#!/usr/bin/env python

import sys, argparse, re, jsbeautifier, base64, binascii, json, pathlib, os
from imports.Signature import Signature, File_Check

os.chdir(sys.path[0])

imports = pathlib.Path('imports').resolve()
outputs = pathlib.Path('outputs').resolve()
json_file = pathlib.Path('imports/Signatures.json').resolve()



Array_VarName = []


def Beautify_JS(ifile):
    
    # Js-Beautifier options
    opts = jsbeautifier.BeautifierOptions
    JS = str(jsbeautifier.beautify_file(ifile, opts))

    opts.indent_size = 4
    opts.indent_with_tabs = True
    opts.editorconfig = False
    opts.eol = '\n'
    opts.end_with_newline = True
    opts.indent_level = 0
    opts.preserve_newlines = True
    opts.max_preserve_newlines = 10
    opts.space_in_paren = True
    opts.space_in_empty_paren = False
    opts.jslint_happy = False
    opts.space_after_anon_function = True
    opts.space_after_named_function = True
    opts.brace_style = 'collapse'
    opts.unindent_chained_methods = False
    opts.break_chained_methods = False
    opts.keep_array_indentation = True
    opts.unescape_strings = False
    opts.wrap_line_length = 0
    opts.e4x = True
    opts.comma_first = False
    opts.indent_empty_lines = False
    opts.templating = ['auto']
    opts.space_before_conditional = True

    #evals JS code. Future setting. 
    opts.eval_code = False
    
    return JS

###############################################################################################################
# Parses and pull data from Base64_array, decodes, then appends resulting files/data to File_list & Signature_Check arrays
def Base64_Stage_Puller(JS, File_List):
    # Checks, validates, and decodes Base64 stages/payloads found in script
    Base64_Array = re.findall(r"((?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/][AQgw]==|[A-Za-z0-9+\/]{2}[AEIMQUYcgkosw048]=)?)", JS, re.MULTILINE)

    # removes unwanted data in Base64_Array
    while("" or '' in Base64_Array):
        if ('' in Base64_Array):
            Base64_Array.remove('')
        if ("" in Base64_Array):
            Base64_Array.remove("")

    # Removes duplicates in Base64_Array
    item = 0
    while Base64_Array.count(Base64_Array[item]) <= 2:
        Base64_Array.remove(Base64_Array[item])
        item += 1
    
    for item in Base64_Array:      
               
        # Finds all Base64 Payloads that are greater than 123 bytes(characters)
        if len(item) >= 123:          
            
            try:
                
                # Attempts to decode Base64 encoded data that have been encoded with UTF-8. (PowerShell, JavaScript, etc).
                data = base64.decodebytes(bytearray(item, 'ascii')).decode('utf-8')
                Base64_Array.remove(item)

                #checks to see if Script Matches Regex values by calling File_Check in Signatures.py then writes to outputs folder if it exists. 
                Signature_Data = File_Check(data)
                
                if Signature_Data:
                    File_Found = Signature_Data    

                    List_Check = []
                    for item in os.listdir(outputs):
                        if item not in List_Check:
                            List_Check.append(item)
                            if item not in File_List:
                                if re.search(rf'(Payload_Stage\d_{File_Found}\.file)', item):
                                    List_Check.remove(item)

                    if len(os.listdir(outputs)) != len(List_Check):
                        if item not in File_List:
                            File_List.append(item)
                            Stage = re.search(rf'Payload_Stage(\d)_{File_Found}\.file', item).group(1)
                            Stage = int(Stage)
                            Stage += 1
                            
                            with open(rf"{outputs}/Payload_Stage{Stage}_{File_Found}.file", 'wb') as payload:
                                payload.write(data)
                    
                    elif len(os.listdir(outputs)) == len(List_Check):
                        
                        Stage = 2
                        
                        with open(rf"{outputs}/Payload_Stage{Stage}_{File_Found}.file", 'wb') as payload:
                            payload.write(data)
                        
                        File_Name = f'Payload_Stage{Stage}_{File_Found}.file'
                        File_List.append(File_Name)    
            
            except UnicodeDecodeError:
                
                # If malware has a Base64 file encoded (PE file for example) the decoding throws a UnicodeDecodeError exception and the file is decoded. 
                data = base64.decodebytes(bytearray(item, 'ascii'))
                Magic_Byte = str(binascii.hexlify(binascii.a2b_base64(item))).replace('b\'', '').replace('\'', '').upper()
                Base64_Array.remove(item)

                # Builds the Magic Byte value from the decoded bytes after conversion to the proper starting length.
                while len(Magic_Byte) >= 13:
                    Magic_Byte = str(Magic_Byte)[:-1]
                
                Magic_Byte = (' '.join(Magic_Byte[i:i+2] for i in range(0,len(Magic_Byte),2)))
                
                # Checks to see if Magic Byte value exists by calling Signature from Signatures.py then writes to outputs folder if it exists. 
                Signature_Data = Signature(Magic_Byte)
                
                if Signature_Data:
                    File_Found = Signature_Data    

                    List_Check = []
                    for item in os.listdir(outputs):
                        if item not in List_Check:
                            List_Check.append(item)
                            if item not in File_List:
                                if re.search(rf'(Payload_Stage\d_{File_Found}\.file)', item):
                                    List_Check.remove(item)

                    if len(os.listdir(outputs)) != len(List_Check):
                        if item not in File_List:
                            File_List.append(item)
                            Stage = re.search(rf'Payload_Stage(\d)_{File_Found}\.file', item).group(1)
                            Stage = int(Stage)
                            Stage += 1
                            
                            with open(rf"{outputs}/Payload_Stage{Stage}_{File_Found}.file", 'wb') as payload:
                                payload.write(data)
                    
                    elif len(os.listdir(outputs)) == len(List_Check):
                        
                        Stage = 2
                        
                        with open(rf"{outputs}/Payload_Stage{Stage}_{File_Found}.file", 'wb') as payload:
                            payload.write(data)
                        
                        File_Name = f'Payload_Stage{Stage}_{File_Found}.file'
                        File_List.append(File_Name)
    
    return File_Found    
###############################################################################################################
# Replaces Variables foundwith their contents with a few exceptions. 
def Variable_Replacer(JS):
    i = 0
    
    # Pulls Full Variable names and their contents.
    Full_Variable = re.findall(r"(^.*var\s.*?\;)", JS, re.MULTILINE)
    Variable_Array = []
    
    # Removes any double spaces for cleanup leaving only single or no spaces. Appends cleaned up data to Variable_Array. 
    for item in Full_Variable:
        var = re.sub(R"\s{2,}", '', item)
        Variable_Array.append(var)
    
    # Goes through each Variable found in Full_Variable, pulls the Variable Name & Contents, then replaces in script. 
    while i >= len(Variable_Array):
        
        VarContents = re.search(r"=(.*?);", Variable_Array[i], re.MULTILINE)
        
        if VarContents:
            
            # Sets up data for current and future use.
            VarContents = str(VarContents.group(1)).strip()
            VarName = re.search(r"var\s(.*?)[=\s]", Variable_Array[i], re.MULTILINE)
            Array_Match = re.search(r"(?!\[\d\])(\[.*?\])", VarContents)
            Function_Match = re.search(r"(\(.*\))", VarContents)
            Index_Match = re.search(r"(\[\d\])", VarContents)
            
            if Array_Match:
                pass
            elif Function_Match:
                pass
            elif Index_Match:
                pass
            else:
                Text_After = JS.replace(Variable_Array[i], '')
                
                if re.search(r'(\"\\\\\")', VarContents, re.MULTILINE):
                    JS = re.sub(rf"\b{VarName.group(1)}\b", r'"\\\\"', Text_After)
                else:
                    JS = re.sub(rf"\b{VarName.group(1)}\b", ' ' + VarContents, Text_After)     
        else:
            pass
        i += 1
    return JS

###############################################################################################################
# Finds and replaces data in array if arrays exist
def Array_Replacer(JS):
    if re.search(r"(.*var.*\[.*?\])", JS, re.MULTILINE):
        Array_Name_Match1 = re.findall(r"var\s(.*?)\s\=\s\[", JS, re.MULTILINE)
        Array_Name_Match2 = re.findall(r"var\s(.*?)\=\[", JS, re.MULTILINE)
        Array_Name_Match3 = re.findall(r"var\s(.*?)\=\s\[", JS, re.MULTILINE)
        Array_Name_Match4 = re.findall(r"var\s(.*?)\s\=\[", JS, re.MULTILINE)
        Array_VarName = []
        CompletedList = []

        # find and append Variable names found
        if Array_Name_Match1:
            VarName = Array_Name_Match1
        elif Array_Name_Match2:
            VarName = Array_Name_Match2 
        elif Array_Name_Match3:
            VarName = Array_Name_Match3
        elif Array_Name_Match4:
            VarName = Array_Name_Match4

        if VarName in Array_VarName:
            pass
        else:
            Array_VarName.append(VarName)

        # Convert and replace Array contents found
        c = 0
        while c < len(Array_VarName[0]):
            Array_Contents_Regex = rf"^.*{Array_VarName[0][c]}[=\s].*\[(.*?)\];"
            Array_Contents_Name = re.search(Array_Contents_Regex, JS, re.MULTILINE)
            
            if Array_Contents_Name:
                
                ArrayContents = str(Array_Contents_Name.group(1)).replace("[", '').replace(']','')
                ContentList = ArrayContents.strip().replace(' ', '').split(',')
                
                i = 0
                b = 0
                while i < len(ContentList):
                    
                    item = Array_VarName[0][c]+"[{}]".format(b).strip()
                    text_after = JS.replace(item, ContentList[i])
                    JS = text_after
                    
                    i += 1
                    b = str(int(b)+1)
                    
                        
                if Array_VarName[0][c] not in CompletedList:
                    CompletedList.append(Array_VarName[0][c])

                c += 1
            else:
                c += 1
    return JS
###############################################################################################################
# Finds and removes all single initialized Variables in code. 
def Single_Init_Variable_Replace(JS):
    VarName_Array = re.findall(r"^.*var\s(.*?)[;\s=]", JS, re.MULTILINE)
    for item in VarName_Array:
        if VarName_Array.count(item) >= 2:
            VarName_Array.remove(item)

    
    i = 0
    c = 0
    while i < len(VarName_Array[0]):
        regex = rf"^var\s{VarName_Array[i]}.*?\;$"
        if JS.count(VarName_Array[i]) == 1:        
            text_after = re.sub(regex, '', JS, flags=re.MULTILINE)
            JS = text_after
            
        i += 1
    return JS
###############################################################################################################
# Writes Deobfuscated JS and payloads found.
def Write_JS(JS):
    Stage_List = []
    if 'Payload_JS.file' not in os.listdir(outputs):
        with open(f"{outputs}/Payload_Deobfuscated_JS.file", 'w') as payload:
            payload.write(JS) 
    
