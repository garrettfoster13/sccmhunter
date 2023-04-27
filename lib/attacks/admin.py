from lib.logger import logger
import sqlite3
import pandas as dp
from tabulate import tabulate
import requests
from requests_ntlm import HttpNtlmAuth
from urllib3.exceptions import InsecureRequestWarning
import warnings
import contextlib
import json
import os
import cmd2


#save for debugging
def jprint(obj):
    text = json.dumps(obj, sort_keys=True, indent=4)
    print(text)
    
#do not delete
headers = {'Content-Type': 'application/json'}


requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class DATABASE:
    def __init__(self, username=None, password=None, url=None, logs_dir=None):
        self.url = url
        self.username = username
        self.password = password
        self.logs_dir = logs_dir
        self._dbname = f"{self.logs_dir}/db/sccmhunter.db"
        self.conn = sqlite3.connect(self._dbname, check_same_thread=False)

    def run(self):
        db_ready = self.validate_tables()
        if db_ready:
            logger.debug("[*] Database built. Collecting data.")
            self.get_devices()
            self.get_users()
            self.get_Pusers()
            self.get_applications()
            self.get_deployments()
            self.get_collections()
        return True


    def validate_tables(self):
        table_names = ["Devices", "Users", "PUsers", "Applications"]
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
            self.conn.execute('''CREATE TABLE Applications(CI_ID, CI_UniqueID,ExecutionContext, IsDeployed, IsEnabled, 
            LocalizedDisplayName, NumberOfDevicesWithApp,NumberOfUsersWithApp, SourceSite)''')
            self.conn.execute('''CREATE TABLE Deployments(ApplicationName,AssignedCI_UniqueID,AssignedCIs,AssignmentName,
            CollectionName,Enabled,NotifyUser,SourceSite,TargetCollectionID)''')
            self.conn.execute('''CREATE TABLE Collections(CollectionID,CollectionType,IsBuiltIn,LimitToCollectionName,MemberClassName,
            MemberCount,Name)''') 
        except Exception as e:
            print(e)
        finally:
            return True

    def get_devices(self):
        logger.info("[*] Collecting devices...")
        cursor = self.conn.cursor()
        endpoint = f'''/SMS_R_System?$select=Active,Client,DistinguishedName,FullDomainName,IPAddresses,
        LastLogonUserDomain,LastLogonUserName,Name,OperatingSystemNameandVersion,PrimaryGroupID,
        ResourceId,ResourceNames,SID,SMSInstalledSites,SMSUniqueIdentifier'''
        r = requests.request("GET",
                            f"{self.url}{endpoint}",
                            auth=HttpNtlmAuth(self.username, self.password),
                            verify=False)
        results = r.json()

        for i in results["value"]:
            Active = str(i["Active"])
            Client = str(i["Client"])
            DistinguishedName = str(i["DistinguishedName"])
            FullDomainName = str(i["FullDomainName"])
            IPAddresses = str(i["IPAddresses"])
            LastLogonUserDomain = str(i["LastLogonUserDomain"])
            LastLogonUserName = str(i["LastLogonUserName"])
            Name = str(i["Name"])
            OperatingSystemNameandVersion = str(i["OperatingSystemNameandVersion"])
            PrimaryGroupID = str(i["PrimaryGroupID"])
            ResourceId = str(i["ResourceId"])
            ResourceNames = str(i["ResourceNames"])
            Sid = str(i["SID"])
            SMSInstalledSites = str(i["SMSInstalledSites"])
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

    def get_users(self):
        logger.info("[*] Collecting users...")
        cursor=self.conn.cursor()
        endpoint = f'''/SMS_R_User?$select=DistinguishedName, FullDomainName, FullUserName, Mail, NetworkOperatingSystem, 
            ResourceId, SID, UniqueUserName, UserAccountControl, UserName, UserPrincipalName'''

        r = requests.request("GET",
                            f"{self.url}{endpoint}",
                            auth=HttpNtlmAuth(self.username, self.password),
                            verify=False)
        results = r.json()

        for i in results["value"]:
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

    def get_Pusers(self):
        logger.info("[*] Collecting user device affinity...")
        cursor=self.conn.cursor()
        endpoint = f'''/SMS_UserMachineRelationship?$select=IsActive,RelationshipResourceID,ResourceID,ResourceName,UniqueUserName'''   
        r = requests.request("GET",
                            f"{self.url}{endpoint}",
                            auth=HttpNtlmAuth(self.username, self.password),
                            verify=False)
        results = r.json()
        for i in results["value"]:
            IsActive = str(i["IsActive"])
            RelationshipResourceID = str(i["RelationshipResourceID"])
            ResourceID = str(i["ResourceID"])
            ResourceName = str(i["ResourceName"])
            UniqueUserName = str(i["UniqueUserName"]) 

            cursor.execute('''insert into PUsers (IsActive,RelationshipResourceID,ResourceID,ResourceName,UniqueUserName) values (?,?,?,?,?)''',(
                IsActive,RelationshipResourceID,ResourceID,ResourceName,UniqueUserName))
        self.conn.commit()


    def get_applications(self):
        logger.info("[*] Collecting applications...")
        cursor=self.conn.cursor()
        endpoint = f'''/SMS_Application?$select=CI_ID,CI_UniqueID,ExecutionContext,IsDeployed,IsEnabled,LocalizedDisplayName,NumberOfDevicesWithApp,
        NumberOfUsersWithApp,SourceSite'''   
        r = requests.request("GET",
                            f"{self.url}{endpoint}",
                            auth=HttpNtlmAuth(self.username, self.password),
                            verify=False)
        results = r.json()
        for i in results["value"]:
            CI_id = str(i["CI_ID"])
            CI_UniqueID = str(i["CI_UniqueID"])
            ExecutionContext = str(i["ExecutionContext"])
            IsDeployed = str(i["IsDeployed"])
            IsEnabled = str(i["IsEnabled"])
            LocalizedDisplayName = str(i["LocalizedDisplayName"])
            NumberOfDevicesWithApp = str(i["NumberOfDevicesWithApp"])
            NumberOfUsersWithApp = str(i["NumberOfUsersWithApp"])
            SourceSite = str(i["SourceSite"])

            cursor.execute('''insert into Applications (CI_ID,CI_UniqueID,ExecutionContext,IsDeployed,IsEnabled,LocalizedDisplayName,NumberOfDevicesWithApp,
            NumberOfUsersWithApp,SourceSite) values (?,?,?,?,?,?,?,?,?)''',(CI_id,CI_UniqueID,ExecutionContext,IsDeployed,IsEnabled,LocalizedDisplayName,NumberOfDevicesWithApp,
            NumberOfUsersWithApp,SourceSite))

        self.conn.commit()

    def get_deployments(self):
        logger.info("[*] Collecting deployments...")
        cursor=self.conn.cursor()
        endpoint = f'''/SMS_ApplicationAssignment?$select=ApplicationName,AssignedCI_UniqueID,AssignedCIs,AssignmentName,CollectionName,Enabled,
        NotifyUser,SourceSite,TargetCollectionID'''   
        r = requests.request("GET",
                            f"{self.url}{endpoint}",
                            auth=HttpNtlmAuth(self.username, self.password),
                            verify=False)
        results = r.json()
        for i in results["value"]:
            ApplicationName = str(i["ApplicationName"])
            AssignedCI_UniqueID = str(i["AssignedCI_UniqueID"])
            AssignedCIs = str(i["AssignedCIs"])
            AssignmentName = str(i["AssignmentName"])
            CollectionName = str(i["CollectionName"])
            Enabled = str(i["Enabled"])
            NotifyUser = str(i["NotifyUser"])
            SourceSite = str(i["SourceSite"])
            TargetCollectionID = str(i["TargetCollectionID"])

            cursor.execute('''insert into Deployments(ApplicationName,AssignedCI_UniqueID,AssignedCIs,AssignmentName,CollectionName,Enabled,
            NotifyUser,SourceSite,TargetCollectionID) values (?,?,?,?,?,?,?,?,?)''', (ApplicationName,AssignedCI_UniqueID,AssignedCIs,AssignmentName,
                                                                                      CollectionName,Enabled,NotifyUser,SourceSite,TargetCollectionID))

        self.conn.commit()


    def get_collections(self):
        logger.info("[*] Collecting collections...")
        cursor=self.conn.cursor()
        endpoint = f'''/SMS_Collection?$select=CollectionID,CollectionType,IsBuiltIn,LimitToCollectionName,MemberClassName,MemberCount,Name'''   
        r = requests.request("GET",
                            f"{self.url}{endpoint}",
                            auth=HttpNtlmAuth(self.username, self.password),
                            verify=False)
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


class CMD(cmd2.Cmd):
    prompt = '>> '

    def __init__(self):
        super().__init__(allow_cli_args=False)

    def do_get(self, arg):
        _dbname = f"/root/.sccmhunter/logs/db/sccmhunter.db"
        conn = sqlite3.connect(_dbname, check_same_thread=False)
        try:
            option = arg.split(' ')
            type = option[0]
            value = " ".join(option[1:])

            if type.lower() in ["device"]:
                tb = dp.read_sql(f'select * from Devices where Name = \'{value}\' COLLATE NOCASE', conn)
                if tb.empty:
                    print(f'[-] Device {value} not found.')
                    return
                logger.info(f'''------------------------------------------
Active: {tb['Active'].to_string(index=False, header=False)}
Client: {tb['Client'].to_string(index=False, header=False)}
DistinguishedName: {tb['DistinguishedName'].to_string(index=False, header=False)}
FullDomainName: {tb['FullDomainName'].to_string(index=False, header=False)}
IPAddresses: {tb['IPAddresses'].to_string(index=False, header=False).replace("['", "").replace("', '", ' ').replace("']", "")}
LastLogonUserDomain: {tb['LastLogonUserDomain'].to_string(index=False, header=False)}
LastLogonUserName: {tb['LastLogonUserName'].to_string(index=False, header=False)}
Name: {tb['Name'].to_string(index=False, header=False)}
OperatingSystemNameandVersion: {tb['OperatingSystemNameandVersion'].to_string(index=False, header=False)}
PrimaryGroupID: {tb['PrimaryGroupID'].to_string(index=False, header=False)}
ResourceId: {tb['ResourceId'].to_string(index=False, header=False)}
ResourceNames: {tb['ResourceNames'].to_string(index=False, header=False).replace("['", "").replace("']", "")}
SID: {tb['SID'].to_string(index=False, header=False)}
SMSInstalledSites: {tb['SMSInstalledSites'].to_string(index=False, header=False).replace("['", "").replace("']", "")}
SMSUniqueIdentifier: {tb['SMSUniqueIdentifier'].to_string(index=False, header=False)}
------------------------------------------''')
                return
        
            if type.lower() in ["user"]:
                tb = dp.read_sql(f'select * from Users where UserName = \'{value}\' COLLATE NOCASE', conn)
                if tb.empty:
                    logger.info(f'[-] User {value} not found.')
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
            if type.lower() in ["puser"]:
                tb = dp.read_sql(f'select * from PUsers where UniqueUserName like \'%{value}\' COLLATE NOCASE', conn)
                if tb.empty:
                    logger.info(f'[-] User {value} not found.')
                    return
                logger.info((tabulate(tb, showindex=False, headers=tb.columns, tablefmt='grid')))

                return
            if type.lower() in ["lastlogon"]:
                tb = dp.read_sql(f'select * from Devices where LastLogonUserName = \'{value}\' COLLATE NOCASE', conn)
                if tb.empty:
                    logger.info(f'[-] User {value} not found.')
                    return
                delete = ["Active", "Client", "PrimaryGroupID", "OperatingSystemNameandVersion", "SMSInstalledSites", "SMSUniqueIdentifier", "SID"]
                for i in delete:
                    del tb[f"{i}"]
                logger.info((tabulate(tb, showindex=False, headers=tb.columns, tablefmt='grid')))
                return

            if type.lower() in ["application"]:
                tb = dp.read_sql(f'select * from Applications where LocalizedDisplayName = \'{value}\' COLLATE NOCASE', conn)
                if tb.empty:
                    logger.info(f'[-] {value} application not found.')
                    return
                for index, row in tb.iterrows():
                    logger.info(f'''---------------------------------------
CI_ID: {row["CI_ID"]}
CI_UniqueID: {row['CI_UniqueID']}
ExecutionContext: {row['ExecutionContext']}
IsDeployed: {row['IsDeployed']}
IsEnabled: {row['IsEnabled']}
LocalizedDisplayName: {row['LocalizedDisplayName']}
NumberOfDevicesWithApp: {row['NumberOfDevicesWithApp']}
NumberOfUsersWithApp: {row['NumberOfUsersWithApp']}
SourceSite: {row['SourceSite']}
------------------------------------------''')
#                 return

            if type.lower() in ["deployment"]:
                tb = dp.read_sql(f'select * from Deployments where ApplicationName = \'{value}\' COLLATE NOCASE', conn)
                if tb.empty:
                    logger.info(f'[-] {value} deployment not found.')
                    return
                logger.info(f'''--------------------------------------
ApplicationName: {tb['ApplicationName'].to_string(index=False, header=False)}
AssignedCI_UniqueID: {tb['AssignedCI_UniqueID'].to_string(index=False, header=False)}
AssignedCIs: {tb['AssignedCIs'].to_string(index=False, header=False).replace("[", ""). replace("]", "")}
AssignmentName: {tb['AssignmentName'].to_string(index=False, header=False)}
CollectionName: {tb['CollectionName'].to_string(index=False, header=False)}
Enabled: {tb['Enabled'].to_string(index=False, header=False)}
NotifyUser: {tb['NotifyUser'].to_string(index=False, header=False)}
SourceSite: {tb['SourceSite'].to_string(index=False, header=False)}
TargetCollectionID: {tb['TargetCollectionID'].to_string(index=False, header=False)}
------------------------------------------''')
                return
            
            if type.lower() in ["collection"]:
                tb = dp.read_sql(f'select * from Collections where Name = \'{value}\' COLLATE NOCASE', conn)
                if tb.empty:
                    logger.info(f'[-] {value} deployment not found.')
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
                return
                

        # probably need some more error handling here
        except KeyboardInterrupt:
            return
        return
        # except Exception as e:
        #     print(e)

    
    def do_help(self, arg):
        print('''Query Commands - Query a target principal from the respective table.
--------
get user [username]
get device [machinename]
get puser [username]
get application [appname]
get collection [collectionname]
get deployment [deploymentid]
get lastlogon [username]

Manual Commands - Manually query the database.
--------
manual [sql query] (not yet implemented)

--------
quit - exit shell
''')



class ADMINSERVICE:

    def __init__(self, username=None, password=None, ip=None, hashes=None, 
                 debug=False, logs_dir = None):
        self.username = username
        self.password = password
        self.ip = ip
        self.hashes = hashes
        self.debug = debug
        self.logs_dir = logs_dir #not sure this is needed  
        self.conn = None
        self._dbname = None
        self.url = f"https://{ip}/AdminService/wmi"

    def run(self):
        if os.path.getsize(f"{self.logs_dir}/db/sccmhunter.db") > 1:
            self.cli()
        else:
            build_db = DATABASE(self.username, self.password, self.url, self.logs_dir)
            db_ready = build_db.run()
            if db_ready:
                self.cli()

    def cli(self):
            cli = CMD()
            cli.cmdloop()


