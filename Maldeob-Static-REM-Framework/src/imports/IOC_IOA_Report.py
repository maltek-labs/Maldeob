#!/usr/bin/env python

import sys, re, base64, binascii, json, pathlib, hashlib, os

os.chdir(sys.path[0])

imports = pathlib.Path('imports').resolve()
outputs = pathlib.Path('outputs/').resolve()
logs = pathlib.Path("outputs/Logs/").resolve()

Binary_Regex = r'(\\x[0-9][0-9]|\\x[a-f][a-f]|\\x[0-9][a-f]|\\x[a-f][0-9])'
IP_Regex = r'(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'
URL_Regex = r'(https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*))'                                                                                            
                                                                                            
header = '''           
#######################################################################################
#                         _  _         _           __         _                       #
#           /\/\    __ _ | || |_  ___ | | __      / /   __ _ | |__   ___              #
#          /    \  / _` || || __|/ _ \| |/ /     / /   / _` || '_ \ / __|             #
#         / /\/\ \| (_| || || |_|  __/|   <     / /___| (_| || |_) |\__ \\             #
#         \/    \/ \__,_||_| \__|\___||_|\_\    \____/ \__,_||_.__/ |___/             #
#######################################################################################
#                               https://maltek-labs.com                               #
#                           -Protection begins with analysis-                         #
#######################################################################################                                                          
                                                
'''

###############################################################################################################

# Create file and Write header. 
with open(f"{logs}/MalwareDetails.txt", 'w') as w:
    w.writelines(header)
    w.close()


def MalwareDetails_Report(ifile):
    ####################################################################### 
    #                       Original File Section                         #
    #######################################################################
    ifile_Name = re.search(r'[\/\\](\w{1,}\.\w{1,})|[\/\\](\w{1,})$', ifile, re.IGNORECASE) 
    Domain_List = []
    IP_List = []
    
    if ifile_Name:
         ifile_Name = re.search(r'[\/\\](\w{1,}\.\w{1,})|[\/\\](\w{1,})$', ifile, re.IGNORECASE).group(1)
    else:
        ifile_Name = re.search(r'[\/\\](\w{1,}\.\w{1,})|[\/\\](\w{1,})$', ifile, re.IGNORECASE).group(2)


    with open(f"{logs}/MalwareDetails.txt", 'w') as w:
        w.writelines(header)
        w.close()


    Original_File_Name = f'''\tOriginal File: {ifile_Name}
    '''

    with open(f"{logs}/MalwareDetails.txt", 'a') as a:
        a.writelines(Original_File_Name)
        a.close
    
    #######################################################################    
    # Calculate Hashes
    MD5 = hashlib.md5()
    SHA1 = hashlib.sha1()
    SHA256 = hashlib.sha256()
        
    with open(ifile, 'rb') as rb:
        Buffer = rb.read()
        MD5.update(Buffer)
        SHA1.update(Buffer)
        SHA256.update(Buffer)
    rb.close()

    MD5 = MD5.hexdigest()
    SHA1 = SHA1.hexdigest()
    SHA256 = SHA256.hexdigest()

    Payload_Hashes = f'''
        File Hashes:
        \tMD5: {MD5}
        \tSHA1: {SHA1}
        \tSHA256: {SHA256}           
        '''
        
    with open(f"{logs}/MalwareDetails.txt", 'a') as a:
        a.writelines(Payload_Hashes)
    a.close()
    MD5 = '' 
    SHA1 = ''
    SHA256 = ''
#######################################################################
# File is ASCII/UTF-8 encoded file (Text file). Searches for IPs & URLs
    try:
        
        with open(ifile, 'r') as r:
            data = r.read()
        r.close()    
        
        if re.search(IP_Regex, data, re.MULTILINE):
            data = re.findall(IP_Regex, data)
            
            Payload_IPs = f'''\n\t\tPotential IPs Found:\n'''

            with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                a.writelines(Payload_IPs)
            a.close()

            i = 0
            while i <= len(data):
                if i >= len(data):
                    pass
                else:
                    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', data[i][0]):
                        IP = data[i][0]
                        if IP not in IP_List:
                            IP_List.append(IP)
                            with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                                a.writelines(f'\t\t\t{IP}\n')
                            a.close()
                i += 1
        #######################################################################
        # Search for URLs/Domains 
                
        with open(ifile, 'r') as r:
            data = r.read()
        r.close()    
        
        if re.search(URL_Regex, data, re.MULTILINE):
            data = re.findall(URL_Regex, data)
            
            Payload_URL_Domains = f'''\n\t\tURLs/Domains Found:\n'''

            with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                a.writelines(Payload_URL_Domains)
            a.close()

            i = 0
            while i <= len(data):
                if i >= len(data):
                    pass
                else:
                    domain = str(data[i][0]).replace('.', '[.]').replace('http', 'hxxp')
                    if domain not in Domain_List:
                        Domain_List.append(domain)
                        
                        with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                            a.writelines(f'\t\t\t{domain}\n')
                        a.close()
                i += 1
    
    except UnicodeDecodeError:
    # File is binary file. Searches for IPs & URLs if UnicodeDecodeError
    #######################################################################
    # Search for IP 
        
        with open(ifile, 'rb') as rb:
            data = str(rb.read())    
        rb.close()

        if re.search(IP_Regex, data, re.MULTILINE):
            data = re.findall(IP_Regex, data)
            
            Payload_IPs = f'''\n\t\tPotential IPs Found:\n'''

            with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                a.writelines(Payload_IPs)
            a.close()

            i = 0
            while i <= len(data):
                if i >= len(data):
                    pass
                else:
                    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', data[i][0]):
                        IP = data[i][0]
                        if IP not in IP_List:
                            IP_List.append(IP)

                            with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                                a.writelines(f'\t\t\t{IP}\n')
                            a.close()
                i += 1
    #######################################################################
    # Search for URLs/Domains     
        Domain_List = []
        
        with open(ifile, 'rb') as rb:
            data = str(rb.read())
        r.close()

        if re.search(URL_Regex, data, re.MULTILINE):
            data = re.findall(URL_Regex, data)
            
            Payload_URL_Domains = f'''\n\t\tURLs/Domains Found:\n'''

            with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                a.writelines(Payload_URL_Domains)
            a.close()

            i = 0
            while i <= len(data):
                if i >= len(data):
                    pass
                else:
                    domain = str(data[i][0]).replace('.', '[.]').replace('http', 'hxxp')
                    
                    if domain not in Domain_List:
                        Domain_List.append(domain)
                        
                        with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                            a.writelines(f'\t\t\t{domain}\n')
                        a.close()
                i += 1
    
    ####################################################################### 
    #               Payloads Found Section                                #
    ####################################################################### 
    for item in os.listdir(outputs):
        File_Path = f'{outputs}/' + f'{item}'

        if re.search('(Payload_.*\.file)', item, re.MULTILINE):
            
            Payload_Name = f'''\n\n\tFile Name: {item}\n'''
            
            with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                a.writelines(Payload_Name)
            a.close()
    #######################################################################    
    # Calculate Hashes
            MD5 = hashlib.md5()
            SHA1 = hashlib.sha1()
            SHA256 = hashlib.sha256()
            
            with open(File_Path, 'rb') as rb:
                Buffer = rb.read()
                MD5.update(Buffer)
                SHA1.update(Buffer)
                SHA256.update(Buffer)
            rb.close()

            MD5 = MD5.hexdigest()
            SHA1 = SHA1.hexdigest()
            SHA256 = SHA256.hexdigest()

            Payload_Hashes = f'''
        File Hashes:
        \tMD5: {MD5}
        \tSHA1: {SHA1}
        \tSHA256: {SHA256}           
        '''
            
            with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                a.writelines(Payload_Hashes)
            a.close()
            MD5 = '' 
            SHA1 = ''
            SHA256 = ''
        #######################################################################
            # Search for IP 
            IP_List = []
            
            try:
                with open(File_Path, 'r') as r:
                    data = r.read()
                r.close()    

                if re.search(IP_Regex, data, re.MULTILINE):
                    data = re.findall(IP_Regex, data)
                    
                    Payload_IPs = f'''\n\t\tPotential IPs Found:\n'''

                    with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                        a.writelines(Payload_IPs)
                    a.close()

                    i = 0
                    while i <= len(data):
                        if i >= len(data):
                            pass
                        else:
                            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', data[i][0]):
                                IP = data[i][0]
                                

                                if IP not in IP_List:
                                    IP_List.append(IP)

                                    with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                                        a.writelines(f'\t\t\t{IP}\n')
                                    a.close()
                        i += 1
 
            except UnicodeDecodeError:
                with open(File_Path, 'rb') as rb:
                    data = str(rb.read())
                rb.close()

                if re.search(IP_Regex, data, re.MULTILINE):
                    data = re.findall(IP_Regex, data)
                    
                    Payload_IPs = f'''\n\t\tPotential IPs Found:\n'''

                    with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                        a.writelines(Payload_IPs)
                    a.close()

                    i = 0
                    while i <= len(data):
                        if i >= len(data):
                            pass
                        else:
                            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', data[i][0]):
                                IP = data[i][0]
                                

                                if IP not in IP_List:
                                    IP_List.append(IP)

                                    with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                                        a.writelines(f'\t\t\t{IP}\n')
                                    a.close()
                        i += 1   
                
        #######################################################################
            # Search for URLs/Domains 
            
            try:
                with open(File_Path, 'r') as r:
                    data = r.read()
                r.close()    

                if re.search(URL_Regex, data, re.MULTILINE):
                    data = re.findall(URL_Regex, data)
                    
                    Payload_URL_Domains = f'''\n\t\tURLs/Domains Found:\n'''

                    with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                        a.writelines(Payload_URL_Domains)
                    a.close()

                    i = 0
                    while i <= len(data):
                        if i >= len(data):
                            pass
                        else:
                            domain = str(data[i][0]).replace('.', '[.]').replace('http', 'hxxp')
                            
                            if domain not in Domain_List:
                                Domain_List.append(domain)
                                
                                with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                                    a.writelines(f'\t\t\t{domain}\n')
                                a.close()
                        i += 1
            except UnicodeDecodeError:
                
                with open(File_Path, 'rb') as rb:
                    data = str(rb.read())
                rb.close()
                
                if re.search(URL_Regex, data, re.MULTILINE):
                    data = re.findall(URL_Regex, data)
                    
                    Payload_URL_Domains = f'''\n\t\tURLs/Domains Found:\n'''

                    with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                        a.writelines(Payload_URL_Domains)
                    a.close()

                    i = 0
                    while i <= len(data):
                        if i >= len(data):
                            pass
                        else:
                            domain = str(data[i][0]).replace('.', '[.]').replace('http', 'hxxp')
                            
                            if domain not in Domain_List:
                                Domain_List.append(domain)
                                
                                with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                                    a.writelines(f'\t\t\t{domain}\n')
                                a.close()
                        i += 1
        #######################################################################                