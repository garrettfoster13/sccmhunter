from lib.logger import logger
import sqlite3
import pandas as dp
from tabulate import tabulate
import requests
from requests_ntlm import HttpNtlmAuth
from urllib3.exceptions import InsecureRequestWarning


headers = {'Content-Type': 'application/json'}
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class DATABASE():
    def __init__(self, username=None, password=None, url=None, logs_dir=None):
        self.url = f"https://{url}/AdminService/wmi"
        self.username = username
        self.password = password
        self.logs_dir = logs_dir
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
            r = requests.request("GET",
                                f"{endpoint}",
                                auth=HttpNtlmAuth(self.username, self.password),
                                verify=False)
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

            r = requests.request("GET",
                                f"{endpoint}",
                                auth=HttpNtlmAuth(self.username, self.password),
                                verify=False)
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
            r = requests.request("GET",
                                f"{endpoint}",
                                auth=HttpNtlmAuth(self.username, self.password),
                                verify=False)
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
        r = requests.request("GET",
                            f"{endpoint}",
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
            r = requests.request("GET",
                                f"{endpoint}",
                                auth=HttpNtlmAuth(self.username, self.password),
                                verify=False)
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

    

