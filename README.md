# Maltek Labs Static REM Framework v0.9.0

Website: https://maltek-labs.com                                   
# 
In-progress static code deobfuscator aimed as deobfuscating malicious code by finding & replacing data, evaluating variables, and more.  

The aim of this project is to have a framework of tools that can be used in order to automate the analysis & deobfuscation of static code for a different number of script/malware types to aide in the initial stages of malware analysis, the extraction IOC/IOAs, the classification of malware, and etc. 

- Tested & works on both Windows & Linux; MacOS not guaranteed

# Instructions: 
1. Install requirements using ```pip install -r requirements.txt```
2. Run main.py by supplying the input file (-i) to malicious file. Inputted file will be read in, analyzed for matching signatures based on file or code type, and resulting code will be beautified, & outputted + any additional stages/payloads found will be outputted to the outputs folder depending on resulting code.  
  
  Example of usage: ```-i "PATH/malware"```

# Frameworks/Projects Incorporated:  
- JS Beautfier Project: https://github.com/beautify-web/js-beautify
- pfysig - Magic Bytes File Signature Detection Project: https://github.com/schlerp/pyfsig - Inspired by & incorporated partial signature list defined in project according to the Creative Commons Attribution-Share-Alike License 3.0 defined in https://en.wikipedia.org/wiki/List_of_file_signatures.
- Decalage2's OleVBA project: https://github.com/decalage2/oletools/wiki/olevba
- DissectMalware's XLMMacroDeobfuscator project: https://github.com/DissectMalware/XLMMacroDeobfuscator (Script will be updated to support Excel 4.0 Macros in v1.0)
- Erocarrea PEFile Multi-platform PE python parser: https://github.com/erocarrera/pefile (Soon to be incorporated in v1.0 release)

# Current script types that are supported:  
  - Jscript/JavaScript
  - VBA
  - PowerShell

# Current file types that are supported:
 - Office Docs (docx, doc, xls, xlsx, etc)
 - PE files (exe, dll, etc)

# Additional Features:
 - Automatic hashing of any files/scripts obtained during runtime in MD5, SHA1, SHA256. 
 - Extraction of IOCs/IOAs from deobfuscated/reverse engineered script. This is outputted to a "Malware_Details.txt" file contained in outputs/logs/ folder. Currently searches for IPs, URLs, Domains, Emails, Registry entries, Bitcoin Crypto Addresses, and Onion Addresses. 
 - Extraction of VBA from malicious documents using OleVBA and subsequently the deobfuscation of VBA code.
 - Additional payload/executable identification & extraction. Extracts additional stages/payloads and performs recursive analysis on each found. 
 - Can be used on standalone script files, PE files, or malicious documents to search for IOCs/IOAs, run any relating pre-coded deobfuscation methods, and output a report containing names, hashes, and IOCs/IOAs found within the files. 
 - Due to deofuscation done, scripts are defanged and will not run preventing infection or execution. 


# Current Deobfuscation features:  
 - JS
    1. Array deobfuscator: Replaces indexed data within the malicious script by automatically pulling an array's contents and replaces indexed data if possible. 
    2. Variable noise removal: Automatic Removal of single initialized but not called variables from scripts. Reduces noise and speeds up analysis. 
    3. JavaScript/JScript beautifier: Uses the js-beautify project to beautifier inputed file to the specified output file. 
    4. Partial variable replacement: Replaces certain variables that are defined with their contents in the script providing better visibility. Google V8's engine is in the works to be incorporated.
    5. Payload extraction: Extracts additional Base64/HEX encoded stages/payloads based upon the signatures detected in Signatures.py. The payloads are then decoded and dropped to output folder in file format "Payload_EXT.file": IE: Payload_JS.file, Payload_PS1.file, Payload_PE.file, etc.

 - VBA
    1. Pulls VBA code using OleVBA decodes strings as much as possible. Saves VBA code as Payload_VBA.file in outputs folder. 
    2. Removes variables in VBA code that have been only initialized once to reduce noise. 
    3. Replaces Variables with their defined contents to provide better insight. 
    4. Decodes and replaces Chrw/Chr functions with associating ASCII characters. 
    5. Finds, replaces, and decodes HEX encoded strings found in VBA code.
    6. Replaces & joins variables that contain strings.
    7. Base64/HEX payload extraction. 
    8. Base64 content decoding and replacement of decoded content. 
 
 - PowerShell
    1. General code clean up (Replaces CHAR values with ascii, newlines from ';', removes defined excessive & useless/ignored characters, etc).
    2. Finds & pulls HEX/Base64 encoded payloads.
    3. Base64 content decoding and replacement of decoded content.
    4. Removes single initialized variables to clean up code. 

# Upcoming features:  
- Automatic JScript/JavaScript variable deobfuscating. Replaces/evals variables to their contents through the inputted script using Googles V8 Engine. 
- Classification of Malicious Scripts via IOCs/IOAs and/or YARA. IE: Trojon/Worm/Virus.(Dropper, Downloader, etc)_REMCOS.RAT
- Extraction of Excel 4.0 Macros using XLMMacroDeofuscator.
- setup.py to aide in the installation of packages. Will be completed on v1.0 release. 


# Upcoming Script/File type(s) to be supported:  
- Excel 4.0 Macros
- PE analysis with pefile

# Current Issues:
- None as of right now. Submit an issues request with sample code or file/script for resolution.

# Help File:
**optional arguments:**
-h, --help		| Show this help message and exit  
--version		| Show program's version number and exit.  
																			 
**required arguments:**
-i INPUT, --input INPUT                                                           
					PATH to malicious script.                                
