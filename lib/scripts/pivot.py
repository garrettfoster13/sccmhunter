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

    def __init__(self, username, password, target, device, logs_dir):
        self.username = username
        self.password = password
        self.target = target
        self.device = device
        self.logs_dir = logs_dir
        self.headers = {'Content-Type': 'application/json; odata=verbose'}
        self.opid = ""
        self.body = ""
    
    def administrators(self):
        body = {"InputQuery":"Administrators"}
        self.do_request(body)
    
    def computer_system(self):
        return
    
    def connection(self):
        return
    
    def desktop(self):
        return
    
    def user(self):
        body = {"InputQuery":"User"}
        self.do_request(body)
    
    def os(self):
        body = {"InputQuery":"OS"}
        self.do_request(body)

    def file(self, arg):
        query = {"InputQuery": ""}
        path = "File('" + arg + "') | distinct FileName, Mode, LastWriteTime, Size, Device" 
        query["InputQuery"] = path
        self.do_request(query)
        return
    
    # this function doesn't work no matter how hard I try
    def file_content(self, arg):
        query = {"InputQuery": ""}
        path = "FileContent('" + arg + "')"
        query["InputQuery"] = path
        self.do_request(query)
        return
    
    def file_share(self):
        body = {"InputQuery":"FileShare"}
        self.do_request(body)
        return
    
    def installed_exe(self):
        body = {"InputQuery":"InstalledExecutable"}
        self.do_request(body)
        return
    
    def installed_software(self):
        body = {"InputQuery":"InstalledSoftware | distinct ProductName, Publisher, ProductVersion"}
        self.do_request(body)
        return
    
    def ipconfig(self):
        body = {"InputQuery":"IPConfig"}
        self.do_request(body)
        return
    
    def logical_disk(self):
        body = {"InputQuery":"LogicalDisk | distinct Device, Description, Caption, DeviceID"}
        self.do_request(body)
        return
    
    def process(self):
        body = {"InputQuery":"Process"}
        self.do_request(body)
        return
        
    def services(self):
        body = {"InputQuery":"Services | distinct Device, Name, PathName, ProcessId, ServiceType, Started"}
        self.do_request(body)
        return
    
    def system_console_user(self):
        body = {"InputQuery":"SystemConsoleUser"}
        self.do_request(body)
        return

    def environment(self):
        body = {"InputQuery":"Environment"}
        self.do_request(body)
        return
        
    def osinfo(self):
        body = {"InputQuery":"OS | distinct Caption, Version, OSArchitecture, Device"}
        self.do_request(body)
        return

    def disk(self):
        body = {"InputQuery":"Disk"}
        self.do_request(body)
        return


    ### Not implemented yet

        
    def registry(self):
        return
    
    def registry_key(self):
        return

    
    

    def do_request(self, body):
        endpoint = f"https://{self.target}/AdminService/v1.0/Device({self.device})/AdminService.RunCMPivot"
        r = requests.post(
                            f"{endpoint}",
                            auth=HttpNtlmAuth(self.username, self.password),
                            json=body,
                            verify=False, 
                            headers=self.headers)
        if not r.status_code == 200:
            logger.info(r.text)
        else: 
            js0n = r.json()
            self.opid = (js0n['value']['OperationId'])
            logger.info(f"Got OperationId {self.opid}. Sleeping 10 seconds to wait for host to call home.")
            time.sleep(10)
            self.get_results()
    

    def get_results(self):
        endpoint = f"https://{self.target}/AdminService/v1.0/Device({self.device})/AdminService.CMPivotResult(OperationId={self.opid})"
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
                data = json.loads(r.text)
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