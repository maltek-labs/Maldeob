#!/usr/bin/env python

import sys, argparse, re, jsbeautifier, base64, binascii, json, pathlib, os, oletools
from imports.Signature import Signature, File_Check
from imports.IOC_IOA_Report import MalwareDetails_Report
from imports.JS import Beautify_JS, Single_Init_Variable_Replace, Array_Replacer, Variable_Replacer, Base64_Stage_Puller, Write_JS
from imports.VBA import Check_VBA, Single_Init_Var, VBA_Var_Replace, VBA_ChrW_Replace, VBA_HEX_Replace, String_Replace

os.chdir(sys.path[0])

imports = pathlib.Path('imports').resolve()
outputs = pathlib.Path('outputs').resolve()
json_file = 'imports/Signatures.json'

###############################################################################################################
print( 
                '''
                #######################################################################################
                #███╗   ███╗ █████╗ ██╗  ████████╗███████╗██╗  ██╗    ██╗      █████╗ ██████╗ ███████╗#
                #████╗ ████║██╔══██╗██║  ╚══██╔══╝██╔════╝██║ ██╔╝    ██║     ██╔══██╗██╔══██╗██╔════╝#
                #██╔████╔██║███████║██║     ██║   █████╗  █████╔╝     ██║     ███████║██████╔╝███████╗#
                #██║╚██╔╝██║██╔══██║██║     ██║   ██╔══╝  ██╔═██╗     ██║     ██╔══██║██╔══██╗╚════██║#
                #██║ ╚═╝ ██║██║  ██║███████╗██║   ███████╗██║  ██╗    ███████╗██║  ██║██████╔╝███████║#
                #╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚═╝  ╚═╝    ╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝#
                #######################################################################################
                #                           https://maltek-labs.com                                   #
                #                       -Protection begins with analysis-                             #
                #                                                                                     #
                #                  Maltek Labs Static REM Framework v0.8.0                            #
                #######################################################################################
                # optional arguments:                                                                 #
                #   -h, --help            Show this help message and exit                             #
                #   --version             Show program's version number and exit.                     #      
                #                                                                                     #
                # required arguments:                                                                 #
                #   -i INPUT, --input INPUT                                                           #
                #                            PATH to malicious script.                                #
                #   -o OUTPUT, --output OUTPUT                                                        #
                #                            PATH to output the completed file.                       #
                #                                                                                     #
                #######################################################################################
                '''
                )
###############################################################################################################

parser = argparse.ArgumentParser(description='Maltek Labs Static REM Framework', prog='Maldeob', add_help=False)

# CMDLine arguments to be passed
parser.add_argument('-h','--help', action='store_true')
parser.add_argument("-i", '--input', help="PATH to malicious script.", type=str)
parser.add_argument('--version', action='version', version='%(prog)s 0.8.0')

# Sets up arguments
args = vars(parser.parse_args())
ifile = args['input']
helpme = args['help']

# Sets up lists for future use
File_List = []

###############################################################################################################

ifile_Name = re.search(r'[\/\\](\w{1,}\.\w{1,})|[\/\\](\w{1,})$', ifile, re.IGNORECASE).group(1)
if ifile_Name:
    pass
else:
    ifile_Name = re.search(r'[\/\\](\w{1,}\.\w{1,})|[\/\\](\w{1,})$', ifile, re.IGNORECASE).group(2)

######################################################################################

def File_Type(ifile):
    try:

        with open(ifile, 'r') as payload:
           payload = payload.read()       
        
        #checks to see if Script Matches Regex values by calling File_Check in Signatures.py then writes to outputs folder if it exists. 
        File_Found = File_Check(payload)    

        return File_Found    
    
    except UnicodeDecodeError:
        
        with open(ifile, 'rb') as payload:
            byte = payload.read(30)
        payload.close()
        # Builds the Bytes in HEX format.
        Magic_Byte = str(binascii.hexlify(byte)).replace('b\'', '').replace('\'', '').upper()
        
        # Builds the Magic Byte value from the decoded bytes after conversion to the proper starting length.
        while len(Magic_Byte) >= 25:
            Magic_Byte = str(Magic_Byte)[:-1]
        Magic_Byte = (' '.join(Magic_Byte[i:i+2] for i in range(0,len(Magic_Byte),2)))
        
        # Checks to see if Magic Byte value exists by calling Signature from Signatures.py then writes to outputs folder if it exists. 
        File_Found = Signature(Magic_Byte)
        
        
        return File_Found

def JS_File(ifile):
    JS = Beautify_JS(ifile)
    JS = Single_Init_Variable_Replace(JS)
    
    if re.search(r".*var.*\[.*?\]", JS, re.MULTILINE):
        JS = Array_Replacer(JS)
    
    JS = Variable_Replacer(JS)
    JS = Single_Init_Variable_Replace(JS)
    
    if re.search(r"((?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/][AQgw]==|[A-Za-z0-9+\/]{2}[AEIMQUYcgkosw048]=)?)", JS, re.MULTILINE):
        Base64_Stage_Puller(JS, File_List)
    
    Write_JS(JS)
    
    return JS

def VBA_File(VBA):
    
    if VBA:
        try: 
            if re.search(r'ChrW\(\d{1,3}\)|Chr\(\d{1,3}\)', VBA, re.MULTILINE):
                Match = True

                VBA = Single_Init_Var(VBA)
                VBA = VBA_ChrW_Replace(VBA)
                VBA = VBA_Var_Replace(VBA)
            elif re.search(r'\"([0-9a-fA-F]{2,})\"|\'([0-9a-fA-F]{2,})\'', VBA, re.MULTILINE):
                Match = True

                VBA = Single_Init_Var(VBA)
                VBA = VBA_Var_Replace(VBA)
                VBA = VBA_HEX_Replace(VBA)
   
            elif re.search(r'\b\w{1,}\b\s=\s\".*?\"|\b\w{1,}\b\s=\s\'.*?\'', VBA, re.MULTILINE):
                Match = True
                VBA = String_Replace(VBA)
            
            if Match:
                with open(f"{outputs}/Payload_Deobfuscated_VBA.file", 'w') as payload:
                    payload.write(VBA)
                payload.close()
                print(f'Deobfuscated VBA Code has been saved to {outputs} as Payload_Deobfuscated_VBA.file.\n')
        except:
            print('No pre-coded matching signatures found for malware obfuscation methods.\n')
            print('Manual investigation & deobfuscation will be needed.\n')

###############################################################################################################
    
if __name__ == "__main__":
    
    if helpme == True:
        exit()
        print('')

    if ifile:
        File = File_Type(ifile)
        
        if File:
            if File == 'JS':
                JS = JS_File(ifile)
                File_List.append('Payload__Deobfuscated_JS.file')
            elif File == 'VBA_File':
                with open(ifile, 'r') as r:
                    VBA = r.read()
                
                VBA = VBA_File(VBA)
            
            elif File == 'PE':
                pass
            
            elif File == 'zip' or 'doc' or 'docx' or 'xlsx' or 'xls' or 'ppt' or 'pptx':
                print(f'\nFile type matched: {File}.  Attempting to check for VBA Code.\n')
                
                VBA = Check_VBA(ifile)
            
                
            for item in os.listdir(outputs):
                
                # Search for File Payloads & types found then run based on script type
                if re.search(r'(Payload_Stage\d_.*\.)file|(Payload_.*\.file)', item):
                    if re.search(r'(Payload_Stage\d_.*\.file)', item):
                        File = re.search(r'(Payload_Stage\d_.*\.)file', item).group(1)
                    else:
                        
                        File = re.search(r'(Payload_.*\.file)', item).group(1)
                    
                    
                    if File not in File_List:
                        File_List.append(File)
                        
                        if re.search(r'(Payload_Stage\d_.*\.)file', item):
                            Script_Type = re.search(r'Payload_Stage\d_(.*?)\.file', item).group(1)
                        else:
                            Script_Type = re.search(r'Payload_(.*?)\.file', item).group(1)

                        # Search for Additional Payloads found then re-run JS_File. 
                        if Script_Type == 'JS':
                            if re.search(r'Payload_Stage\d_JS\.file', item):
                                Stage = re.search(rf'Payload_Stage(\d)_JS\.file', item).group(1)
                                Stage = int(Stage)
                                
                                JS = JS_File(f'{outputs}/Payload_Stage{Stage}_JS.file')
                            
                        
                        elif Script_Type == 'VBA':
                            print(f'Now attempting to deobfuscate VBA code. This may take some time depending on size of file & VBA content.\n')
                            VBA = VBA_File(VBA)
        else:
            print('File is not supported as of yet.')

    # Writes IOCs/IOAs from within original file & stages/payloads found
    MalwareDetails_Report(ifile)
 
    print('##############################################################################################################\n')
    print('')
    print('Script has been completed. Press enter to exit\n')
    input()
    exit()
