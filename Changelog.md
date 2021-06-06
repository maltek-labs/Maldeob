# What's New? 

**Update: v0.7.0**
- Fixed array's JavaScript/JScript variable names + contents from not being properly picked up & replaced. Arrays/contents are now picked up
- Completed Partial variable replacement. Replaces certain variables that are defined with their contents in the script providing better visability. Google V8's engine is in the works to be incorporated.
- Added Automatic additional Stage/payload extraction: Extracts additional Base64 encoded malware stages/payloads based upon the Magic Byte signatures in Signatures.json in the decoded content. The payloads are then decoded and dropped to output folder in file format "Payload_EXT.file": IE: Payload_JS.file, Payload_PS1.file, Payload_PE.file, etc. Detection for PS1 & JavaScript/JScript will be in the next update.
- Code adjustments for faster runtime/analysis.  
- Added Changelog.md to project to track changes.