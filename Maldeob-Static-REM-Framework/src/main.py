#!/usr/bin/env python

import sys, argparse, re, binascii, pathlib, os
from imports.Signature import Signature, File_Check
from imports.IOC_IOA_Report import MalwareDetails_Report
from imports.JS import JS_File
from imports.VBA import Check_VBA, VBA_File
from imports.PS1 import PowerShell_File
from imports.UnZip import Unzip_File

os.chdir(sys.path[0])

imports = pathlib.Path('imports').resolve()
outputs = pathlib.Path('outputs').resolve()

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
                #                  Maltek Labs Static REM Framework v0.9.0                            #
                #######################################################################################
                # optional arguments:                                                                 #
                #   -h, --help            Show this help message and exit                             #
                #   --version             Show program's version number and exit.                     #      
                #                                                                                     #
                # required arguments:                                                                 #
                #   -i INPUT, --input INPUT                                                           #
                #                            PATH to malicious script.                                #
                #                                                                                     #
                #######################################################################################
                '''
                )
###############################################################################################################

parser = argparse.ArgumentParser(description='Maltek Labs Static REM Framework', prog='Maldeob', add_help=False)

# CMDLine arguments to be passed
parser.add_argument('-h','--help', action='store_true')
parser.add_argument("-i", '--input', help="PATH to malicious script.", type=str)
parser.add_argument('--version', action='version', version='%(prog)s 0.9.0')

# Set up arguments
args = vars(parser.parse_args())
ifile = args['input']
helpme = args['help']

# Set up lists for future use
File_List = []

###############################################################################################################

def File_Type(ifile):
    try:
        
        with open(ifile, 'r') as payload:
           payload = payload.read()       

        # Checks to see if Script Matches Regex values by calling File_Check in Signatures.py then writes to outputs folder if it exists.
        File_Found = File_Check(payload)    

        return File_Found    
    
    except UnicodeDecodeError:
        # Upon decode and a UniDecodeError occurs, error handling will occur as a binary file has been detected instead of base UTF-8 encoded file. 
        with open(ifile, 'rb') as payload:
            byte = payload.read(30)
        
        # Builds the Bytes in HEX format.
        Magic_Byte = str(binascii.hexlify(byte)).replace('b\'', '').replace('\'', '').upper()
        
        # Builds the Magic Byte value from the decoded bytes after conversion to the proper starting length.
        while len(Magic_Byte) >= 25:
            Magic_Byte = str(Magic_Byte)[:-1]
        Magic_Byte = (' '.join(Magic_Byte[i:i+2] for i in range(0,len(Magic_Byte),2)))
        
        # Checks to see if Magic Byte value exists by calling Signature from Signatures.py then writes to outputs folder if it exists. 
        File_Found = Signature(Magic_Byte)
        
        return File_Found

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
                File_List.append('Payload_JS.file')
            
            elif File == 'VBA_File':
                with open(ifile, 'r') as r:
                    VBA = r.read()
                r.close()
                
                VBA = VBA_File(VBA)
                File_List.append('Payload_VBA.file')

            elif File == 'PS1':
                with open(ifile, 'r') as r:
                    PS_Code = r.read()
                r.close()
                
                PowerShell_File(PS_Code)
            
            elif File == 'PE':
                pass
            
            elif File == 'zip' or 'doc' or 'docx' or 'xlsx' or 'xls' or 'ppt' or 'pptx':
                print(f'\nFile type matched: {File}.  Attempting to check for VBA Code.\n')
                
                VBA = Check_VBA(ifile)
            
            i = 0
            Dir_List = os.listdir(outputs)
            
            for item in Dir_List:
                
                # Search for File Payloads & types found then run based on script type
                if re.search(r'Payload_.*\.file', item):                      
                    File = re.search(r'(Payload_.*\.file)', item).group(1)
                    
                    if File not in File_List:
                        File_List.append(File)
                        
                        if re.search(r'(Payload_Stage\d_.*\.)file', item):
                            Script_Type = re.search(r'Payload_Stage\d_(.*?)\.file', item).group(1)
                        else:
                            Script_Type = re.search(r'Payload_(.*?)\.file', item).group(1)

                        # Search for Additional Payloads found then re-run JS_File. 
                        if Script_Type == 'JS':
                            
                            JS = JS_File(f'{outputs}/{File}')
                            
                        
                        elif Script_Type == 'VBA':
                            print(f'Now attempting to deobfuscate VBA code. This may take some time depending on size of file & VBA content.\n')
                            VBA = VBA_File(VBA)
                        
                        elif Script_Type == 'GZ':
                            data = Unzip_File(item)
                
                Dir_List = os.listdir(outputs)
                i += 1
        else:
            print('File is not supported as of yet.')

    # Writes IOCs/IOAs from within original file & stages/payloads found
    print('\nNow building report. \n    Please wait...\n\n')
    MalwareDetails_Report(ifile)
 
    print('\t######################################################################################################\n')
    print('')
    print('Script has been completed. Press enter to exit\n')
    input()
    exit()