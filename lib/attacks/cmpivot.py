import cmd2
import pandas as dp
import requests
from requests_ntlm import HttpNtlmAuth
import json
from urllib3.exceptions import InsecureRequestWarning
import time
from tabulate import tabulate
from lib.scripts.banner import show_banner
from lib.logger import logger, logger

#todo
#Desktop - see if screensaver is active
#FileContent - read provided file path
#FileShare - see available fileshares on the host








requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

#add debugging

class CMD(cmd2.Cmd):
    prompt = '>> '
    
    
    def __init__(self, username, password, url):
        super().__init__(allow_cli_args=False)
        self.username = username
        self.password = password
        self.url = url
        self.headers = {'Content-Type': 'application/json'}

    def do_administrators(self, arg):
        endpoint = f"https://{self.url}/AdminService/v1.0/Device({arg})/AdminService.RunCMPivot"
        body = {"InputQuery":"Administrators"}
        r = requests.post(
                            f"{endpoint}",
                            auth=HttpNtlmAuth(self.username, self.password),
                            json=body,
                            verify=False, 
                            headers=self.headers,)
        if not r.status_code == 200:
            print(r.text)
        else: 
            json = r.json()
            opid = (json['value']['OperationId'])
            logger.info(f"Got OperationId {opid}. Sleeping 10 seconds to wait for host to call home.")
            time.sleep(10)
            self.get_results(deviceid=arg, opid=opid)

    def do_ipconfig(self, arg):
        endpoint = f"https://{self.url}/Adminservice/v1.0/Device({arg})/AdminService.RunCMPivot"
        body = {"InputQuery":"IPConfig"}
        r = requests.post(
                            f"{endpoint}",
                            auth=HttpNtlmAuth(self.username, self.password),
                            json=body,
                            verify=False, 
                            headers=self.headers,)
        if not r.status_code == 200:
            logger.info("Something went wrong")
        else: 
            json = r.json()
            opid = (json['value']['OperatproceionId'])
            logger.info(f"Got OperationId {opid}. Sleeping 10 seconds to wait for host to call home.")
            time.sleep(10)
            self.get_results(deviceid=arg, opid=opid)

    #having issues accepting a filepath
    #hardcoding the path works fine but using a string formatter fails.
    def do_file(self, arg):
        option = arg.split(' ')
        device = option[0]
        filepath = " ".join(option[1:])
        endpoint = f"https://{self.url}/AdminService/v1.0/Device({device})/AdminService.RunCMPivot"
        body = {"InputQuery" : "File('C:/Users/*')"}
        r = requests.post(
                            f"{endpoint}",
                            auth=HttpNtlmAuth(self.username, self.password),
                            json=body,
                            verify=False, 
                            headers=self.headers,)
        print(r.request.body)
        if not r.status_code == 200:
            logger.info(r.text)
            logger.info(r.status_code)
            logger.info("Something went wrong")
        else: 
            json = r.json()
            opid = (json['value']['OperationId'])
            logger.info(f"Got OperationId {opid}. Sleeping 10 seconds to wait for host to call home.")
            time.sleep(10)
            self.get_results(deviceid=arg, opid=opid)

    def do_process(self, arg):
        endpoint = f"https://{self.url}/AdminService/v1.0/Device({arg})/AdminService.RunCMPivot"
        body = {"InputQuery":"Process"}
        r = requests.post(
                            f"{endpoint}",
                            auth=HttpNtlmAuth(self.username, self.password),
                            json=body,
                            verify=False, 
                            headers=self.headers,)
        if not r.status_code == 200:
            logger.info("Something went wrong")
        else: 
            json = r.json()
            opid = (json['value']['OperationId'])
            logger.info(f"Got OperationId {opid}. Sleeping 10 seconds to wait for host to call home.")
            time.sleep(10)
            self.get_results(deviceid=arg, opid=opid)

    def get_results(self, deviceid, opid):
        opid = opid
        deviceid = deviceid
        endpoint = f"https://{self.url}/AdminService/v1.0/Device({deviceid})/AdminService.CMPivotResult(OperationId={opid})"
        try:
            r = requests.request("GET",
                                f"{endpoint}",
                                auth=HttpNtlmAuth(self.username, self.password),
                                verify=False)
            if r.status_code == 404:
                logger.info("No results yet, sleeping 10 seconds.")
                time.sleep(10)
                self.get_results(deviceid, opid)
            data = json.loads(r.text)
            tb = dp.DataFrame(data['value']['Result'])
            logger.info(tabulate(tb, showindex=False, headers=tb.columns, tablefmt='grid'))
        except Exception as e:
            logger.info(e)



    #not implemented yet
    # def do_environment(self, arg):
    #     endpoint = f"https://{self.url}/AdminService/v1.0/Device({arg})/AdminService.RunCMPivot"
    #     body = {"InputQuery":"Environment"}
    #     r = requests.post(
    #                         f"{endpoint}",
    #                         auth=HttpNtlmAuth(self.username, self.password),
    #                         json=body,
    #                         verify=False, 
    #                         headers=self.headers,)
    #     if not r.status_code == 200:
    #         logger.info("Something went wrong")
    #     else: 
    #         json = r.json()
    #         opid = (json['value']['OperationId'])
    #         logger.info(f"Got OperationId {opid}. Sleeping 10 seconds to wait for host to call home.")
    #         time.sleep(10)
    #         self.get_results(deviceid=arg, opid=opid)
            
    def do_help(self, arg):
        logger.info('''Run CMPivot queries remotely using the AdminService API. Proof of concept for now.
-------- 
administrators (devicecode)                         Query local administrators of target device.                      
ipconfig (devicecode)                               Query TCP/IP network configuraiton of target device.                       
process (devicecode)                                Query runnning processes of target device.
--------
quit - exit shell
''')
              

class CMPIVOT:
    def __init__(self, username=None, password=None, ip=None, debug=False):
        self.username = username
        self.password = password
        self.url = ip
        self.debug = debug
    
    def run(self):
        try:
            endpoint = f"https://{self.url}/AdminService/wmi/"
            r = requests.request("GET",
                                endpoint,
                                auth=HttpNtlmAuth(self.username, self.password),
                                verify=False)
            if r.status_code == 200:
                self.cli()
            if r.status_code == 401:
                logger.info("Got error code 401: Access Denied. Check your credentials.")
        except Exception as e:
            logger.info("An unknown error occurred, use -debug to print the response")
            logger.info(e)



    def cli(self):
        cli = CMD(self.username, self.password, self.url)
        cli.cmdloop()



if __name__ == '__main__':
    import sys
    c = CMD()
    sys.exit(c.cmdloop())                                                                                                                                                                                                                            


    
                                                                                                                                                                                                                           