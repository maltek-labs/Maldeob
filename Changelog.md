# What's New? 

**Major update: v0.9.0**
- Added PowerShell Script analysis support with the following below:
    1. General code clean up (Replaces CHAR values with ascii, newlines from ';', removes defined excessive & useless/ignored characters, etc).
    2. Finds & pulls HEX/Base64 encoded payloads.
    3. Base64 content decoding and replacement of decoded content.
    4. Removes single initialized variables to clean up code. 
- Improved Base64 payload extraction and deobfuscation of content in JS/VBA methods.
- General code improvements and performance increases during analysis.
- Recursive file analysis. All extracted payload/stages are analyzed as found. 
- Added Unzip.py to handle zip files found. 
- Improved IOC/IOA gathering by including Domains, Emails, Registry entries, Bitcoin Crypto Addresses, and Onion Addresses.

**Major update: v0.8.0**
- Added VBA support via OleVBA. 
- Added 5 known obfuscation methods to be programically deobfuscated for VBA code.
- Minor changes to JavaScript/Jscript handling + deobfuscation.  
- Added MalwareDetails.txt report to be generated after deobfuscation + code extraction has been completed. 
- Added support for standalone script files, PE files, and binary files (xls, docx, xlsx, etc)
- Added file & script type signatures detection via Signature.py
- Major code rework to allow future changes & allow any file to be ran to pull IOCs + hashing of the file(s)

**Minor Update: v0.7.1**
- Fixed path bug due to structure change upon previous upload. Minor version updates in code. 


**Major Update: v0.7.0**
- Fixed array's JavaScript/JScript variable names + contents from not being properly picked up & replaced. Arrays/contents are now picked up
- Completed Partial variable replacement. Replaces certain variables that are defined with their contents in the script providing better visibility. Google V8's engine is in the works to be incorporated.
- Added Automatic additional Stage/payload extraction: Extracts additional Base64 encoded malware stages/payloads based upon the Magic Byte signatures in Signatures.json in the decoded content. The payloads are then decoded and dropped to output folder in file format "Payload_EXT.file": IE: Payload_JS.file, Payload_PS1.file, Payload_PE.file, etc. Detection for PS1 & JavaScript/JScript will be in the next update.
- Code adjustments for faster runtime/analysis.  
- Added Changelog.md to project to track changes.
