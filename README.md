# Maltek Labs Static REM Framework v0.7.0

Website: https://maltek-labs.com                                   
# 
In-progress static code deobfuscator aimed as deobfuscating malicious code by finding & replacing data, evaluating variables, and more.  

The aim of this project is to have a framework of tools that can be selected in order to automate the deobfuscation for a different number of script/malware types to aide in the initial stages of malware analysis, the extraction IOC/IOAs, and the classification of malware. 

- Tested & works on both Windows & Linux

# Instructions: 
1. Install requirements using ```pip install -r requirements.txt```
2. Run main.py by supplying the input file (-i) to malicious script (with original file extension[IE: .js]), + (-o) with name of file with extension of choosing. Inputted file will be read in, beautified, & outputted file + any additional stages/payloads found will be outputted to the outputs folder. ```-i PATH/malware.js -o output.js```

# Frameworks/Projects Incorporated:  
- JS Beautfier Project: https://github.com/beautify-web/js-beautify
- pfysig - Magic Bytes File Signature Detection Project: https://github.com/schlerp/pyfsig - Inspired by & incorporated partial signature list defined in project according to the Creative Commons Attribution-Share-Alike License 3.0 defined in https://en.wikipedia.org/wiki/List_of_file_signatures. 

# Current script types that are supported:  
  - Jscript/JavaScript

# Current features:  
1. Array deobfuscator: Replaces indexed data within the malicious script by automatically pulling the an array's contents and replaces indexed data if possible. 
2. Variable noise removal: Automatic Removal of initialized but not called variables from scripts. Reduces noise and speeds up analysis. 
3. JavaScript/JScript beautifier: Uses the js-beautify project to beautifier inputed file to the specified output file. 
4. Partial variable replacement: Replaces certain variables that are defined with their contents in the script providing better visibility. Google V8's engine is in the works to be incorporated.
5. Automatic additional Stage/payload extraction: Extracts additional Base64 encoded malware stages/payloads based upon the Magic Byte signatures in Signatures.json in the decoded content. The payloads are then decoded and dropped to output folder in file format "Payload_EXT.file": IE: Payload_JS.file, Payload_PS1.file, Payload_PE.file, etc. Detection for PS1 & JavaScript/JScript will be in the next update. 

# Upcoming features:  
- Automatic JScript/JavaScript variable deobfuscating. Replaces/evals variables to their contents through the inputted script using Googles V8 Engine 
- Extraction of IOC/IOAs from deobfuscated/reverse engineered script. This will be outputted to a "Malware_Details.txt" file. 
- Classification of Malicious Scripts via IOCs/IOAs and/or YARA. IE: Trojon/Worm/Virus.(Dropper, Downloader, etc)_REMCOS.RAT
- Automatic hashing of any files/scripts obtained during runtime in MD5, SHA1, SHA256. 
- setup.py to aide in the installation of packages. Will be completed on v1.0 release. 

# Upcoming Script type(s) supported:  
- Powershell

# Current Issues:
- None as of right now. Submit an issues request with sample code or file/script for resolution.

# Help File:
**optional arguments:**
-h, --help		| Show this help message and exit  
--version		| Show program's version number and exit.  
																			 
**required arguments:**
-i INPUT, --input INPUT                                                           
					PATH to malicious script.                                
-o OUTPUT, --output OUTPUT                                                        
					PATH to output the completed file.
