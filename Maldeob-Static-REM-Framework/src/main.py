#!/usr/bin/env python

import sys, argparse, re, jsbeautifier, base64, binascii, json, pathlib
from imports.JS import Variable_Replacer, Stage_Puller, Array_Replacer

imports = pathlib.Path('imports').resolve()
outputs = pathlib.Path('outputs').resolve()
json_file = imports / 'Signatures.json'

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
                #                  Maltek Labs Static REM Framework(WIP) v0.7.1                       #
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

parser = argparse.ArgumentParser(description=' Maltek Labs Static REM Framework(WIP)', prog='Maldeob', add_help=False)

#cmdline arguments to be passed
parser.add_argument('-h','--help', action='store_true')
parser.add_argument("-i", '--input', help="PATH to malicious script.", type=str)
parser.add_argument("-o", "--output", help="PATH to output the completed file.", type=str)
parser.add_argument('--version', action='version', version='%(prog)s 0.7.1')

#sets up arguments
args = vars(parser.parse_args())
ifile = args['input']
ofile = args['output']
helpme = args['help']

# Regex to pull input file extension
if ifile:
    File_Extension = re.search(r'(?i)(\..*?$)', ifile, re.MULTILINE).group(1)

###############################################################################################################
if ifile:
    if re.search('.js', File_Extension, re.IGNORECASE):

    #Js-Beautifier options
        opts = jsbeautifier.BeautifierOptions
        Converted_Text = str(jsbeautifier.beautify_file(ifile, opts))

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

###############################################################################################################
    # Arrays
        Array_VarName = []
        CompletedList = []
        Variable_Array = []
        File_list = []
        Signature_Check = []
        VarName_Array = re.findall(r"^.*var\s(.*?)[;\s=]", Converted_Text, re.MULTILINE)
        Base64_Array = re.findall(r"((?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/][AQgw]==|[A-Za-z0-9+\/]{2}[AEIMQUYcgkosw048]=)?)", Converted_Text, re.MULTILINE)
        Full_Variable = re.findall(r"(^.*var\s.*?\;)", Converted_Text, re.MULTILINE)
        Array_Name_Match1 = re.findall(r"var\s(.*?)\s\=\s\[", Converted_Text, re.MULTILINE)
        Array_Name_Match2 = re.findall(r"var\s(.*?)\=\[", Converted_Text, re.MULTILINE)
        Array_Name_Match3 = re.findall(r"var\s(.*?)\=\s\[", Converted_Text, re.MULTILINE)
        Array_Name_Match4 = re.findall(r"var\s(.*?)\s\=\[", Converted_Text, re.MULTILINE)
            
###############################################################################################################
    # Clean up list data

        for item in Full_Variable:
            var = re.sub(R"\s{2,}", '', item)
            Variable_Array.append(var)

        for item in VarName_Array:
            if VarName_Array.count(item) >= 2:
                VarName_Array.remove(item)

##############################################################################################################

     
if __name__ == "__main__":
    
    if helpme == True:
        exit()
        print('')

    Stage_Puller(Base64_Array, File_list, Signature_Check)
    Converted_Text = Variable_Replacer(Converted_Text, Variable_Array)
    Converted_Text = Array_Replacer(Converted_Text, Array_Name_Match1, Array_Name_Match2, Array_Name_Match3, Array_Name_Match4, Array_VarName, CompletedList, VarName_Array)
 
    with open(f'{outputs}/' + f'{ofile}', 'w') as w:
        w.write(Converted_Text.strip().replace('\n',''))
        print('##############################################################################################################')
        print('')
        print(Rf'The file has been outputted to: {outputs} as '+ ofile) 
        print('')
        print('Press enter to exit')
        input()
        exit()
