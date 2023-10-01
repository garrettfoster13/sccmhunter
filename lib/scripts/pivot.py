import requests
from requests_ntlm import HttpNtlmAuth
from urllib3.exceptions import InsecureRequestWarning
import json
import time
from tabulate import tabulate
import pandas as dp
from lib.logger import logger
from datetime import datetime


class CMPIVOT:

    def __init__(self, username, password, target, logs_dir):
        self.username = username
        self.password = password
        self.target = target
        self.logs_dir = logs_dir
        self.headers = {'Content-Type': 'application/json; odata=verbose'}
        self.opid = ""
        self.body = ""
        self.device = ""
        self.endpoint = ""
    
    def administrators(self, device):
        body = {"InputQuery":"Administrators"}
        self.device = device
        self.do_request(body)
    
    def computer_system(self):
        return
    
    def connection(self):
        return
    
    def desktop(self):
        return
    
    def user(self, device):
        self.device=device
        body = {"InputQuery":"User"}
        self.do_request(body)
    
    def os(self, device):
        self.device = device
        body = {"InputQuery":"OS"}
        self.do_request(body)

    def file(self, arg, device):
        query = {"InputQuery": ""}
        path = "File('" + arg + "') | distinct FileName, Mode, LastWriteTime, Size, Device" 
        query["InputQuery"] = path
        self.device = device
        self.do_request(query)
        return
    
    # this function doesn't work no matter how hard I try
    # used a script instead open a PR please!!
    # def file_content(self, arg):
    #     query = {"InputQuery": ""}
    #     path = "FileContent('" + arg + "')"
    #     query["InputQuery"] = path
    #     self.do_request(query)
    #     return
    
    def file_share(self, device):
        self.device = device
        body = {"InputQuery":"FileShare"}
        self.do_request(body)
        return
    
    def installed_exe(self):
        body = {"InputQuery":"InstalledExecutable"}
        self.do_request(body)
        return
    
    def installed_software(self, device):
        self.device=device
        body = {"InputQuery":"InstalledSoftware | distinct ProductName, Publisher, ProductVersion"}
        self.do_request(body)
        return
    
    def ipconfig(self, device):
        self.device = device
        body = {"InputQuery":"IPConfig"}
        self.do_request(body)
        return
    
    def logical_disk(self, device):
        self.device = device
        body = {"InputQuery":"LogicalDisk | distinct Device, Description, Caption, DeviceID"}
        self.do_request(body)
        return
    
    def process(self, device):
        body = {"InputQuery":"Process"}
        self.device = device
        self.do_request(body)
        return
        
    def services(self, device):
        self.device = device
        body = {"InputQuery":"Services | distinct Device, Name, PathName, ProcessId, ServiceType, Started"}
        self.do_request(body)
        return
    
    def system_console_user(self, device):
        body = {"InputQuery":"SystemConsoleUser"}
        self.device = device
        self.do_request(body)
        return

    def environment(self, device):
        self.device = device
        body = {"InputQuery":"Environment"}
        self.do_request(body)
        return
        
    def osinfo(self, device):
        self.device = device
        body = {"InputQuery":"OS | distinct Caption, Version, OSArchitecture, Device"}
        self.do_request(body)
        return

    def disk(self, device):
        self.device = device
        body = {"InputQuery":"Disk"}
        self.do_request(body)
        return
    ### Not implemented yet

        
    def registry(self):
        return
    
    def registry_key(self):
        return

    def do_request(self, body):
        if self.device[0].isdigit():
            self.endpoint = "Device"
        if self.device[0].isalpha():
            self.endpoint = "Collections"
            self.device = f"'{self.device}'"
        endpoint = f"https://{self.target}/AdminService/v1.0/{self.endpoint}({self.device})/AdminService.RunCMPivot"
        try:
            r = requests.post(
                                f"{endpoint}",
                                auth=HttpNtlmAuth(self.username, self.password),
                                json=body,
                                verify=False, 
                                headers=self.headers)
            if r.status_code == 200:
                js0n = r.json()
                if self.endpoint == "Collections":
                    self.opid=(js0n['OperationId'])
                    logger.debug("Querying Collections")
                elif self.endpoint == "Device":
                    logger.debug("Querying Devices")
                    self.opid = (js0n['value']['OperationId'])
                logger.info(f"Got OperationId {self.opid}. Sleeping 10 seconds to wait for host to call home.")
                time.sleep(10)
                self.get_results()                    
            else:
                logger.info("Something went wrong.")
                logger.info(r.status_code)
                logger.info(r.text) 
        except Exception as e:
            logger.info(f"An error occurred: {e}")

    

    def get_results(self):
        endpoint = f"https://{self.target}/AdminService/v1.0/{self.endpoint}({self.device})/AdminService.CMPivotResult(OperationId={self.opid})"
        while True:
            try:
                r = requests.request("GET",
                                    f"{endpoint}",
                                    auth=HttpNtlmAuth(self.username, self.password),
                                    verify=False)
                if r.status_code == 404:
                    logger.info("No results yet, sleeping 10 seconds.")
                    time.sleep(10)
                    continue
                data = r.json()
                if isinstance(data['value'], list):
                    for entry in data['value']:
                        tb = dp.DataFrame(entry['Result'])
                        result = tabulate(tb, showindex=False, headers=tb.columns, tablefmt='grid')
                        logger.info(result)
                        self.printlog(result)
                else:
                    tb = dp.DataFrame(data['value']['Result'])
                    result = tabulate(tb, showindex=False, headers=tb.columns, tablefmt='grid')
                    logger.info(result)
                    self.printlog(result)
                return
            except Exception as e:
                logger.info(e)
                return

    def jprint(self, data):
        try:
            text = json.dumps(data, sort_keys=True, indent=4)
            logger.info(text)
        except ValueError:
            return
        

    def printlog(self, result):
        filename = (f'{self.logs_dir}/console.log')
        dt = datetime.now()
        ts = str(dt)
        with open(filename, 'a') as f:
            f.write("\n--------"+ ts + "--------\n")
            f.write("\n{}\n".format(result))
            f.close