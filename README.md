# Maltek Labs Replacer/Deobfuscator Framework(WIP) v.1 
Current feature set still in developement. 

Website: https://maltek-labs.com                                   
#
In-progress static code deobfuscator aimed as deobfuscating malicious code by finding & replacing data, evaluating variables, and more. The aim of this project is to have a framework of tools that can be selected in order to automate the deobfuscation for a different number of script types.

Current features:  
1. Array deobfuscator: Replaces indexed data within the malicious script with the supplied array. 


Current scripts types that are supported:  

  - Jscript/JavaScript


Upcoming features:  
- Inline node.js support
- Automatic JScript/JavaScript variable deobfucating


# Instructions:

1. Array must be manually pulled from script and saved in a seperate file with each value on a new line. Extra characters that are not part of the array (commas, semi-colons, etc) must be manually removed. 
2. Once the contents of the array has been saved use the arguments below to run the script
                                                            
-h, --help            show this help message and exit  
-a ARRAY, --array ARRAY  PATH to array file  
-i INPUT, --input INPUT  PATH to inputfile  
-o OUTPUT, --output OUTPUT  PATH to output the completed file.
