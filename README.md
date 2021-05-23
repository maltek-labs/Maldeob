# Maltek Labs Replacer/Deobfuscator Framework(WIP) v0.6 

Website: https://maltek-labs.com                                   
#
In-progress static code deobfuscator aimed as deobfuscating malicious code by finding & replacing data, evaluating variables, and more. The aim of this project is to have a framework of tools that can be selected in order to automate the deobfuscation for a different number of script types.

# Current script types that are supported:  
  - Jscript/JavaScript

# Current features:  
1. Array deobfuscator: Replaces indexed data within the malicious script by automatically pulling the an array's contents and replaces indexed data if possible. 
2. Variable noise removal: Automatic Removal of initialized but not called variables from scripts. Reduces noise and speeds up analysis. 
3. JavaScript/JScript beautifier: Uses the js-beautify project located at: https://github.com/beautify-web/js-beautify to beautifier inputed file to the specified output file. 

# Upcoming features:  
- Automatic JScript/JavaScript variable deobfuscating (Replaces/evals variables to their contents through the inputted script.)
- Automatic Stage/payload extraction (Extracts additional malware stages/payloads and drops to current folder.)


# Help File:

optional arguments:
-h, --help            Show this help message and exit                             
-a, --array           Use -a if malicious script contains an array indexing       
				                obfuscation method. EG (array_name[0], array_name[1], etc)
-v, --variable        Use -v to find all instances of variables that are          
				                initialized but not called. Removes variable noise.       
--version             Show program's version number and exit.                     
																			 
required arguments:                                                                 
-i INPUT, --input INPUT                                                           
					PATH to malicious script.                                
-o OUTPUT, --output OUTPUT                                                        
					PATH to output the completed file.

# Instructions: 
Run Maldeob.py by supplying the input file (-i) and path + filename to output file (-o) in beautified format. Supply optional arguments as needed. 
