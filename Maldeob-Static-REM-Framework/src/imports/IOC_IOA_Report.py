#!/usr/bin/env python

import sys, binascii, pathlib, hashlib, os
import regex as re

os.chdir(sys.path[0])

imports = pathlib.Path('imports').resolve()
outputs = pathlib.Path('outputs/').resolve()
logs = pathlib.Path("outputs/Logs/").resolve()

###############################################################################################################

BinaryHex_Regex = r'(\\x[0-9][0-9]|\\x[a-f][a-f]|\\x[0-9][a-f]|\\x[a-f][0-9])'
IP_Regex = r'(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'
URL_Regex = r'(?i)((?:https?|ftp):\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*))'
Domain_Regex = r'(\b((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}\b)'
Email_Regex = r'(\b[A-Za-z0-9.!#$%&\'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)'
Registry_Regex = r'(?i)((hk((EY_(CLASSES_ROOT|PERFORMANCE_DATA|LOCAL_MACHINE|CURRENT_(CONFIG|USER)|USERS))|LM|CR|CU|U|CC|PD))\\[\\\w\}\{\.\-\ \*]+)'
CryptoAddress_Regex = r'(\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,42}\b)'
onionAddress_Regex = r'\b[a-z2-7]{16}\.onion\b|\b[a-z2-7]{56}\.onion\b'

Excluded_matches = r'(?i)\w{1,}\.(?:exe|dll|js|png|jpg|php|split|text|cfg|reloc|bindingflags)'

IP_List = []
URL_List = []
Domain_List = []
Email_List = []
Registry_List = []
Crypto_List = []
Onion_List = []


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
    ifile_Name = re.search(r'[\/\\](.[a-zA-F0-9()_,. -]{1,})$', ifile, re.IGNORECASE).group(1)

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
            File_Contents = r.read()
        r.close()    
        
        if re.search(IP_Regex, File_Contents, re.MULTILINE):
            data = re.findall(IP_Regex, File_Contents)

            i = 0
            while i <= len(data):
                if i >= len(data):
                    pass
                else:
                    if re.search(r'\d{1,3}\.0\.0\.0', data[i][0]):
                        pass
                    else:
                        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', data[i][0]):
                            IP = data[i][0]
                            if IP not in IP_List:
                                IP_List.append(IP)
                i += 1
            data.clear()

        #######################################################################
        # Search for URLs/Domains     
        
        if re.search(URL_Regex, File_Contents, re.MULTILINE):
            data = re.findall(URL_Regex, File_Contents)
            
            i = 0
            while i <= len(data):
                if i >= len(data):
                    pass
                else:
                    URL = str(data[i][0]).replace('.', '[.]').replace('http', 'hxxp')

                    if URL not in URL_List:
                        URL_List.append(URL)
                i += 1
            data.clear()

        if re.search(Domain_Regex, File_Contents, re.MULTILINE):
            data = re.findall(Domain_Regex, File_Contents)
            
            i = 0
            while i <= len(data):
                if i >= len(data):
                    pass
                else:
                    domain = str(data[i][0])
                    if domain not in Domain_List:
                        Domain_List.append(domain)
                        
                i += 1
            data.clear()

        #######################################################################
        # Search for Emails 
        
        if re.search(Email_Regex, File_Contents, re.MULTILINE):
            data = re.findall(Email_Regex, File_Contents)

            i = 0
            while i <= len(data):
                if i >= len(data):
                    pass
                else:
                    email = str(data[i])
                    if email not in Email_List:
                        Email_List.append(email)
                i += 1
            data.clear()

        #######################################################################
        # Search for Registry Entries 
        
        if re.search(Registry_Regex, File_Contents, re.MULTILINE):
            data = re.findall(Registry_Regex, File_Contents)

            i = 0
            while i <= len(data):
                if i >= len(data):
                    pass
                else:
                    registry = str(data[i][0])
                    if registry not in Registry_List:
                        Registry_List.append(registry)
                i += 1
            data.clear()

        #######################################################################
        # Search for Crypto Addresses
        
        if re.search(CryptoAddress_Regex, File_Contents, re.MULTILINE):
            data = re.findall(CryptoAddress_Regex, File_Contents)
            
            i = 0
            while i <= len(data):
                if i >= len(data):
                    pass
                else:
                    crypto = str(data[i])
                    if crypto not in Crypto_List:
                        Crypto_List.append(crypto)
                i += 1
            data.clear()

        #######################################################################
        # Search for Onion Addresses 
        
        if re.search(onionAddress_Regex, File_Contents, re.MULTILINE):
            data = re.findall(onionAddress_Regex, File_Contents)

            i = 0
            while i <= len(data):
                if i >= len(data):
                    pass
                else:
                    onion = str(data[i])
                    if onion not in Onion_List:
                        Onion_List.append(onion)
                i += 1
            data.clear()

    except UnicodeDecodeError:
    # File is binary file. Searches for IPs & URLs if UnicodeDecodeError
    #######################################################################
    # Search for IP 
        
        with open(ifile, 'rb') as rb:
            File_Contents = str(rb.read())
        r.close()    
        
        if re.search(IP_Regex, File_Contents, re.MULTILINE):
            data = re.findall(IP_Regex, File_Contents)

            i = 0
            while i <= len(data):
                if i >= len(data):
                    pass
                else:
                    if re.search(r'\d{1,3}\.0\.0\.0', data[i][0]):
                        pass
                    else:
                        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', data[i][0]):
                            IP = data[i][0]
                            if IP not in IP_List:
                                IP_List.append(IP)
                i += 1
            data.clear()

        #######################################################################
        # Search for URLs/Domains  
        
        if re.search(URL_Regex, File_Contents, re.MULTILINE):
            data = re.findall(URL_Regex, File_Contents)

            i = 0
            while i <= len(data):
                if i >= len(data):
                    pass
                else:
                    URL = str(data[i][0]).replace('.', '[.]').replace('http', 'hxxp')
                    if URL not in URL_List:
                        URL_List.append(URL)
                i += 1
            data.clear()

        if re.search(Domain_Regex, File_Contents, re.MULTILINE):
            data = re.findall(Domain_Regex, File_Contents)
            
            i = 0
            while i <= len(data):
                if i >= len(data):
                    pass
                else:
                    domain = str(data[i][0])
                    if domain not in Domain_List:
                        Domain_List.append(domain)
                i += 1
            data.clear()

        #######################################################################
        # Search for Emails 
        
        if re.search(Email_Regex, File_Contents, re.MULTILINE):
            data = re.findall(Email_Regex, File_Contents)

            i = 0
            while i <= len(data):
                if i >= len(data):
                    pass
                else:
                    email = str(data[i][0])
                    if email not in Email_List:
                        Email_List.append(email)
                i += 1
            data.clear()

        #######################################################################
        # Search for Registry Entries 
        
        if re.search(Registry_Regex, File_Contents, re.MULTILINE):
            data = re.findall(Registry_Regex, File_Contents)

            i = 0
            while i <= len(data):
                if i >= len(data):
                    pass
                else:
                    registry = str(data[i][0])
                    if registry not in Registry_List:
                        Registry_List.append(registry)
                i += 1
            data.clear()
            
        #######################################################################
        # Search for Crypto Addresses
        
        if re.search(CryptoAddress_Regex, File_Contents, re.MULTILINE):
            data = re.findall(CryptoAddress_Regex, File_Contents)

            i = 0
            while i <= len(data):
                if i >= len(data):
                    pass
                else:
                    crypto = str(data[i])
                    if crypto not in Crypto_List:
                        Crypto_List.append(crypto)
                i += 1
            data.clear()

        #######################################################################
        # Search for Onion Addresses 
        
        if re.search(onionAddress_Regex, File_Contents, re.MULTILINE):
            data = re.findall(onionAddress_Regex, File_Contents)
            
            i = 0
            while i <= len(data):
                if i >= len(data):
                    pass
                else:
                    onion = str(data[i])
                    if onion not in Onion_List:
                        Onion_List.append(onion)
                i += 1
            data.clear()

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
            
            try:
                with open(File_Path, 'r') as r:
                    File_Contents = r.read()
                r.close()    

                if re.search(IP_Regex, File_Contents, re.MULTILINE):
                    data = re.findall(IP_Regex, File_Contents)

                    i = 0
                    while i <= len(data):
                        if i >= len(data):
                            pass
                        else:
                            if re.search(r'\d{1,3}\.0\.0\.0', data[i][0]):
                                pass
                            else:
                                if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', data[i][0]):
                                    IP = data[i][0]
                                    if IP not in IP_List:
                                        IP_List.append(IP)
                        i += 1
                    data.clear()

                #######################################################################
                # Search for URLs/Domains     
                
                if re.search(URL_Regex, File_Contents, re.MULTILINE):
                    data = re.findall(URL_Regex, File_Contents)

                    i = 0
                    while i <= len(data):
                        if i >= len(data):
                            pass
                        else:
                            URL = str(data[i][0]).replace('.', '[.]').replace('http', 'hxxp')
                            if URL not in URL_List:
                                URL_List.append(URL)
                        i += 1
                    data.clear()

                if re.search(Domain_Regex, File_Contents, re.MULTILINE):
                    data = re.findall(Domain_Regex, File_Contents)
                    
                    i = 0
                    while i <= len(data):
                        if i >= len(data):
                            pass
                        else:
                            domain = str(data[i][0])
                            if domain not in Domain_List:
                                Domain_List.append(domain)
                        i += 1
                    data.clear()

                #######################################################################
                # Search for Emails 
                
                if re.search(Email_Regex, File_Contents, re.MULTILINE):
                    data = re.findall(Email_Regex, File_Contents)

                    i = 0
                    while i <= len(data):
                        if i >= len(data):
                            pass
                        else:
                            email = str(data[i][0])
                            if email not in Email_List:
                                Email_List.append(email)
                        i += 1
                    data.clear()

                #######################################################################
                # Search for Registry Entries 
                
                if re.search(Registry_Regex, File_Contents, re.MULTILINE):
                    data = re.findall(Registry_Regex, File_Contents)

                    i = 0
                    while i <= len(data):
                        if i >= len(data):
                            pass
                        else:
                            registry = str(data[i][0])
                            if registry not in Registry_List:
                                Registry_List.append(registry)
                        i += 1
                    data.clear()

                #######################################################################
                # Search for Crypto Addresses
                
                if re.search(CryptoAddress_Regex, File_Contents, re.MULTILINE):
                    data = re.findall(CryptoAddress_Regex, File_Contents)

                    i = 0
                    while i <= len(data):
                        if i >= len(data):
                            pass
                        else:
                            crypto = str(data[i])
                            if crypto not in Crypto_List:
                                Crypto_List.append(crypto)
                        i += 1
                    data.clear()

                #######################################################################
                # Search for Onion Addresses 
                
                if re.search(onionAddress_Regex, File_Contents, re.MULTILINE):
                    data = re.findall(onionAddress_Regex, File_Contents)

                    i = 0
                    while i <= len(data):
                        if i >= len(data):
                            pass
                        else:
                            onion = str(data[i])
                            if onion not in Onion_List:
                                Onion_List.append(onion)
                        i += 1
                    data.clear()

            except UnicodeDecodeError:
                
                with open(File_Path, 'rb') as rb:
                    File_Contents = str(rb.read())
                rb.close()

                if re.search(IP_Regex, File_Contents, re.MULTILINE):
                    data = re.findall(IP_Regex, File_Contents)

                    i = 0
                    while i <= len(data):
                        if i >= len(data):
                            pass
                        else:
                            if re.search(r'\d{1,3}\.0\.0\.0', data[i][0]):
                                pass
                            else:
                                if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', data[i][0]):
                                    IP = data[i][0]
                                    if IP not in IP_List:
                                        IP_List.append(IP)
                        i += 1
                    data.clear()

                #######################################################################
                # Search for URLs/Domains     
                
                if re.search(URL_Regex, File_Contents, re.MULTILINE):
                    data = re.findall(URL_Regex, File_Contents)

                    i = 0
                    while i <= len(data):
                        if i >= len(data):
                            pass
                        else:
                            URL = str(data[i][0]).replace('.', '[.]').replace('http', 'hxxp')
                            if URL not in URL_List:
                                URL_List.append(URL)
                        i += 1
                    data.clear()

                if re.search(Domain_Regex, File_Contents, re.MULTILINE):
                    data = re.findall(Domain_Regex, File_Contents)
                    
                    i = 0
                    while i <= len(data):
                        if i >= len(data):
                            pass
                        else:
                            domain = str(data[i][0])
                            if domain not in Domain_List:
                                Domain_List.append(domain)
                        i += 1
                    data.clear()

                #######################################################################
                # Search for Emails 
                
                if re.search(Email_Regex, File_Contents, re.MULTILINE):
                    data = re.findall(Email_Regex, File_Contents)

                    i = 0
                    while i <= len(data):
                        if i >= len(data):
                            pass
                        else:
                            email = str(data[i][0])
                            if email not in Email_List:
                                Email_List.append(email)
                        i += 1
                    data.clear()

                #######################################################################
                # Search for Registry Entries 
                
                if re.search(Registry_Regex, File_Contents, re.MULTILINE):
                    data = re.findall(Registry_Regex, File_Contents)

                    i = 0
                    while i <= len(data):
                        if i >= len(data):
                            pass
                        else:
                            registry = str(data[i][0])
                            if registry not in Registry_List:
                                Registry_List.append(registry)
                        i += 1
                    data.clear()

                #######################################################################
                # Search for Crypto Addresses
                
                if re.search(CryptoAddress_Regex, File_Contents, re.MULTILINE):
                    data = re.findall(CryptoAddress_Regex, File_Contents)
                    
                    i = 0
                    while i <= len(data):
                        if i >= len(data):
                            pass
                        else:
                            crypto = str(data[i])
                            if crypto not in Crypto_List:
                                Crypto_List.append(crypto)
                        i += 1
                    data.clear()

                #######################################################################
                # Search for Onion Addresses 
                
                if re.search(onionAddress_Regex, File_Contents, re.MULTILINE):
                    data = re.findall(onionAddress_Regex, File_Contents)
                    
                    i = 0
                    while i <= len(data):
                        if i >= len(data):
                            pass
                        else:
                            onion = str(data[i])
                            if onion not in Onion_List:
                                Onion_List.append(onion)
                        i += 1
                    data.clear()


    if IP_List or URL_List or Domain_List or Email_List or Registry_List or Crypto_List or Onion_List:
        Payload_Details = '''\n\n\tIOC/IOA(s) Found:\n'''

        with open(f"{logs}/MalwareDetails.txt", 'a') as a:
            a.writelines(Payload_Details)
        a.close()
        
        #######################################################################
        # Write IPs  
        
        if IP_List:
            Payload_Details = '''\n\t\tIP(s) Found:\n'''

            with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                a.writelines(Payload_Details)
            
            IP_List.sort()
            for item in IP_List:
                with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                    a.writelines(f'\t\t\t{item}\n')
            a.close()
        
        #######################################################################
        # Write URLs  
        
        if URL_List:
            Payload_Details = '''\n\t\tURL(s) Found:\n'''

            with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                a.writelines(Payload_Details)
            URL_List.sort()
            for item in URL_List:
                with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                    a.writelines(f'\t\t\t{item}\n')
            a.close()
        
        #######################################################################
        # Write Domains  
        
        if Domain_List:
            Payload_Details = '''\n\t\tPotential Domains Found:\n'''

            with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                a.writelines(Payload_Details)
            
            Domain_List.sort()
            for item in Domain_List:
                if not re.search(Excluded_matches, item, re.MULTILINE):
                    with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                        a.writelines(f'\t\t\t{item}\n')
            a.close()
        
        #######################################################################
        # Write Onion Addresses  
        
        if Onion_List:
            Payload_Details = '''\n\t\tOnion Address(es) Found:\n'''

            with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                a.writelines(Payload_Details)
            
            Onion_List.sort()
            for item in Onion_List:
                with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                    a.writelines(f'\t\t\t{item}\n')
            a.close()
        
        #######################################################################
        # Write Registry  
        
        if Registry_List:
            Payload_Details = '''\n\t\tRegistry Entries Found:\n'''

            with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                a.writelines(Payload_Details)
            
            Registry_List.sort()
            for item in Registry_List:
                with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                    a.writelines(f'\t\t\t{item}\n')
            a.close()
        
        #######################################################################
        # Write Emails  
        
        if Email_List:
            Payload_Details = '''\n\t\tEmails(s) Found:\n'''

            with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                a.writelines(Payload_Details)
            
            Email_List.sort()
            for item in Email_List:
                with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                    a.writelines(f'\t\t\t{item}\n')
            a.close()
        
        #######################################################################
        # Write Crypto Addresses  
        
        if Crypto_List:
            Payload_Details = '''\n\t\tPotential Crypto Address(es) Found:\n'''
            
            with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                a.writelines(Payload_Details)
            
            Crypto_List.sort()
            for item in Crypto_List:
                with open(f"{logs}/MalwareDetails.txt", 'a') as a:
                    a.writelines(f'\t\t\t{item}\n')
            a.close()