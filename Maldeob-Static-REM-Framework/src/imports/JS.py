#!/usr/bin/env python

import sys, argparse, re, jsbeautifier, base64, binascii, json, pathlib

imports = pathlib.Path('imports').resolve()
outputs = pathlib.Path('outputs').resolve()
json_file = imports / 'Signatures.json'

###############################################################################################################
# Parses and pull data from Base64_array, decodes, then appends resulting files/data to File_list & Signature_Check arrays

def Stage_Puller(Base64_Array, File_list, Signature_Check):
    for item in Base64_Array:
        if Base64_Array.count(item) >= 2:
                while("" or '' in Base64_Array):
                        Base64_Array.remove('')
                        Base64_Array.remove("")  
        
                while Base64_Array.count(item) >= 2:
                        Base64_Array.remove(item)
        if len(item) >= 123:
            File_list.append(base64.decodebytes(bytearray(item, 'ascii')))
            Base64_Array.remove(item)
            
            while len(item) >= 17:
                item = str(item)[:-1]
            
            Base64_Array.append(item)
            data = str(binascii.hexlify(binascii.a2b_base64(item))).replace('b\'', '').replace('\'', '').upper()
            Signature_Check.append(' '.join(data[i:i+2] for i in range(0,len(data),2)))

    # Loads signatures from Signatures.json
    with open(json_file, 'r') as data:
        data = json.load(data)

    # Checks signatures for matches based on magic byte value and outputs resulting file
    for item in Signature_Check:
        while not list(filter(lambda x:x["hex"] == item, data)):
            if not list(filter(lambda x:x["hex"] == item, data)):
                item = item[:-3]
            else:
                pass
        
        if list(filter(lambda x:x["hex"] == item, data)):
            File_Found = list(filter(lambda x:x["hex"] == item, data))[0]['file_extension']
            print('Signature(s) matched: \n\n'+ str(list(filter(lambda x:x["hex"] == item, data))[0]))
            print('')
        else:
            return False
            


        item = 0
        while item < len(File_list):
            with open(f"{outputs}/Payload_{File_Found}.file", 'wb') as payload:
                payload.write(File_list[item])

            item += 1

###############################################################################################################
# Replaces Variables foundwith their contents with a few exceptions. 

def Variable_Replacer(Converted_Text, Variable_Array):
    i = 0
    while i < len(Variable_Array):
        
        VarContents = re.search(r"=(.*?);", Variable_Array[i], re.MULTILINE)
        
        if VarContents:
            
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
                Text_After = Converted_Text.replace(Variable_Array[i], '')
                
                if re.search(r'(\"\\\\\")', VarContents, re.MULTILINE):
                    Converted_Text = re.sub(rf"\b{VarName.group(1)}\b", r'"\\\\"', Text_After)
                else:
                    Converted_Text = re.sub(rf"\b{VarName.group(1)}\b", ' ' + VarContents, Text_After)     
        else:
            pass
        i += 1
    return Converted_Text

###############################################################################################################
# Finds and replaces data in array if arrays exist

def Array_Replacer(Converted_Text, Array_Name_Match1, Array_Name_Match2, Array_Name_Match3, Array_Name_Match4, Array_VarName, CompletedList, VarName_Array):
    if re.search(r"(.*var.*\[.*?\])", Converted_Text, re.MULTILINE):
    
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
            Array_Contents_Name = re.search(Array_Contents_Regex, Converted_Text, re.MULTILINE)
            
            if Array_Contents_Name:
                
                ArrayContents = str(Array_Contents_Name.group(1)).replace("[", '').replace(']','')
                ContentList = ArrayContents.strip().replace(' ', '').split(',')
                
                i = 0
                b = 0
                while i < len(ContentList):
                    
                    item = Array_VarName[0][c]+"[{}]".format(b).strip()
                    text_after = Converted_Text.replace(item, ContentList[i])
                    Converted_Text = text_after
                    
                    i += 1
                    b = str(int(b)+1)
                    
                        
                if Array_VarName[0][c] not in CompletedList:
                    CompletedList.append(Array_VarName[0][c])

                c += 1
            else:
                c += 1

    i = 0
    c = 0
    while i < len(VarName_Array[0]):
        regex = rf"^var\s{VarName_Array[i]}.*?\;$"
        if Converted_Text.count(VarName_Array[i]) == 1:        
            text_after = re.sub(regex, '', Converted_Text, flags=re.MULTILINE)
            Converted_Text = text_after
            
        i += 1
    return Converted_Text
###############################################################################################################
