#improvement ideas:
#make the list of site servers a set

from lib.ldap import init_ldap_session, get_dn
import ldap3
from ldap3.utils.conv import escape_filter_chars
import json
import os
import csv
from tabulate import tabulate
import pandas as pd
from getpass import getpass
from lib.logger import logger, printlog
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, ACCESS_ALLOWED_ACE
import copy
from lib.scripts.banner import show_banner
import sqlite3
import pandas as dp


class DACLPARSE:

    def __init__(self):
        self.security_descriptor = SR_SECURITY_DESCRIPTOR()

    @property
    def dacl(self):
        return self.security_descriptor["Dacl"]
    
    @property
    def owner_sid(self):
        return self.security_descriptor['OwnerSid'] 


class DATABASE:

    def __init__(self, logs_dir=None):
        self.database = f"{logs_dir}/db/find.db"
        self.conn = sqlite3.connect(self.database, check_same_thread=False)


    def run(self):
        db_ready = self.validate_tables()
        if db_ready:
            logger.debug("[*] Database built.")
            return True

    def validate_tables(self):
        table_names = ["SiteServers", "ManagementPoints", "Users", "Groups", "Computers"]
        try:
            for table_name in table_names:
                validated = self.conn.execute(f'''select name FROM sqlite_master WHERE type=\'table\' and name =\'{table_name}\'
                ''').fetchall()
                if len(validated) == 0:
                    self.build_tables()
            return True
        except Exception as e:
            logger.info("[-] Something went wrong creating tables.")
            logger.info(f"[-] {e}")
            exit()

    def build_tables(self):
        logger.debug("[*] First time run detected. Building database")
        try:
            self.conn.execute('''CREATE TABLE SiteServers(Hostname, SiteCode, SigningStatus, SiteServer, Active, Passive, MSSQL)''')
            self.conn.execute('''CREATE TABLE ManagementPoints(Hostname, SiteCode, SigningStatus)''')
            self.conn.execute('''CREATE TABLE Users(cn, name, sAMAAccontName, servicePrincipalName, description)''')
            self.conn.execute('''CREATE TABLE Groups(cn, name, sAMAAccontName, member, description)''')
            self.conn.execute('''CREATE TABLE Computers(Hostname, SiteCode, SigningStatus, SiteServer, ManagementPoint, DistributionPoint, WSUS, MSSQL)''')
        except Exception as e:
            logger.info(f"{e}")
        finally:
            return True
    
    def show_table(self, table_name):
        try:
            tb = dp.read_sql(f'select * from {table_name} COLLATE NOCASE', self.conn)
            logger.info((tabulate(tb, showindex=False, headers=tb.columns, tablefmt='grid')))
        except Exception as e:
            logger.info(e)




class SCCMHUNTER:
    
    def __init__(self, username=None, password=None, domain=None, target_dom=None, 
                 dc_ip=None,ldaps=False, kerberos=False, no_pass=False, hashes=None, 
                 aes=None, debug=False, logs_dir = None):
        self.username = username
        self.password= password
        self.domain = domain
        self.target_dom = target_dom
        self.dc_ip = dc_ip
        self.ldaps = ldaps
        self.kerberos = kerberos
        self.no_pass = no_pass
        self.hashes=hashes
        self.aes = aes
        self.debug = debug
        self.ldap_session = None
        self.search_base = None
        self.servers = []
        self.logs_dir = logs_dir
        self.controls = ldap3.protocol.microsoft.security_descriptor_control(sdflags=0x07)
        self.database = f"{logs_dir}/db/find.db"
        self.conn = sqlite3.connect(self.database, check_same_thread=False)
        self.resolved_sids = []


    def run(self):

        #make sure the DB is built
        db = DATABASE(self.logs_dir)
        db.run()

        #bind to ldap
        if not self.ldap_session:
            self.ldapsession()

        # set search base to query
        if self.target_dom:
            self.search_base = get_dn(self.target_dom)
        else:
            self.search_base = get_dn(self.domain)

        #check for AD extension
        self.check_schema()
        #if they're using DNS only: thoughts and prayers
        self.check_strings()

        if self.servers:
            self.results()

        self.conn.close()

    def check_schema(self):
        # Query the ACL Of the System Management container for FULL CONTROL permissions. This container
        # is created during optional extension of the Active Directory schema to allow site servers to publish 
        # to LDAP.
        logger.info(f'[*] Checking for System Management Container.')
        try:
            self.ldap_session.extend.standard.paged_search(self.search_base, 
                                                           search_filter="(cn=System Management)", 
                                                           attributes="nTSecurityDescriptor", 
                                                           controls=self.controls,
                                                           paged_size=500, 
                                                           generator=False)
            if self.ldap_session.entries:
                for entry in self.ldap_session.entries:
                    logger.info("[+] Found System Management Container. Parsing DACL.")
                    json_entry = json.loads(entry.entry_to_json())
                    attributes = json_entry['attributes'].keys()
                    dacl = DACLPARSE()
                    for attr in attributes:
                        secdesc = (entry[attr].value)
                        dacl.security_descriptor.fromString(secdesc)
                self.ace_parser(dacl)

            if self.resolved_sids:
                cursor = self.conn.cursor()
                for result in self.resolved_sids:
                    cursor.execute(f'''insert into SiteServers (Hostname, SiteCode, SigningStatus, SiteServer, Active, Passive, MSSQL) values (?,?,?,?,?,?,?)''',
                                   (result, '', '', 'True', '', '', '')) 
                    self.conn.commit()

                cursor.execute('''SELECT COUNT (Hostname) FROM SiteServers''')
                count = cursor.fetchone()[0]
                logger.info(f'[+] Found {count} computers with Full Control ACE')
                cursor.close()
                self.check_mps()
            else:
                logger.info("[-] System Management Container not found.")
        except ldap3.core.exceptions.LDAPAttributeError as e:
            logger.info("[-] Did not find System Management Container")
            return
        except Exception as e:
            logger.info(e)


    def check_mps(self):
        # Now query for the mssmsmanagementpoint object class. If schema exists there should be at least one.
        # Add to the site servers array // this might be redundant if we're querying for them specifically
        logger.info(f'[*] Querying LDAP for published Management Points')
        cursor = self.conn.cursor()
        try:
            self.ldap_session.extend.standard.paged_search(self.search_base, 
                                                           "(objectclass=mssmsmanagementpoint)", 
                                                           attributes=["dNSHostName", "msSMSSiteCode"], 
                                                           controls=self.controls, 
                                                           paged_size=500, 
                                                           generator=False)  
            if self.ldap_session.entries:
                logger.info(f"[+] Found {len(self.ldap_session.entries)} Management Points in LDAP.")
                for entry in self.ldap_session.entries:
                    hostname =  str(entry['dNSHostname'])
                    sitecode = str(entry['msSMSSitecode'])
                    self.servers.append(str(hostname).lower())
                    cursor.execute(f'''insert into ManagementPoints (Hostname, SiteCode, SigningStatus) values (?,?,?)''',
                                   (hostname, sitecode, '')) 
                    self.conn.commit()
        except ldap3.core.exceptions.LDAPObjectClassError as e:
            logger.info(f'[-] Could not find any Management Points published in LDAP')


    def check_strings(self):
        #now search for anything related to "SCCM" 
        yeet = '(|(samaccountname=*sccm*)(samaccountname=*mecm*)(description=*sccm*)(description=*mecm*)(name=*sccm*)(name=*mecm*))'
        logger.info("[*] Searching LDAP for anything containing the strings 'SCCM' or 'MECM'")
        try:
            self.ldap_session.extend.standard.paged_search(self.search_base, 
                                                           yeet, 
                                                           attributes="*", 
                                                           paged_size=500, 
                                                           generator=False)  
        except ldap3.core.exceptions.LDAPAttributeError as e:
            logger.info(f'Error: {str(e)}')
        
        
        if self.ldap_session.entries:
            cursor = self.conn.cursor()
            logger.info(f"[+] Found {len(self.ldap_session.entries)} principals that contain the string 'SCCM' or 'MECM'.")
            for entry in self.ldap_session.entries:
                try:
                    #add user to db
                    if (entry['sAMAccountType']) == 805306368:
                        self.add_user_to_db(entry)
                    #add computer to db
                    if (entry['sAMAccountType']) == 805306369:
                        self.add_computer_to_db(entry)
                    #add group to db and resolve members
                    if (entry['sAMAccountType']) == 268435456:
                        dn = (entry['distinguishedname'])
                        results = self.recursive_resolution(dn)
                        for result in results:
                            if (result['sAMAccountType']) == 805306368:
                                self.add_user_to_db(result)
                            if (result['sAMAccountType']) == 805306369:
                                self.add_computer_to_db(result)
                except ldap3.core.exceptions.LDAPAttributeError as e:
                    logger.debug(f"[-] {e}")
                except ldap3.core.exceptions.LDAPKeyError as e:
                    logger.debug(f"[-] {e}")
        else:
            logger.info("[-] No results found.")


    def add_user_to_db(self, entry):
        cursor = self.conn.cursor()
        cn = str(entry['cn']) if 'cn' in entry else ''
        name = str(entry['name']) if 'name' in entry else ''
        sam = str(entry['sAMAccountName']) if 'sAMAccountName' in entry else ''
        spn = str(entry['servicePrincipalName']) if 'servicePrincipalName' in entry else ''
        description = str(entry['description']) if 'description' in entry else ''
        cursor.execute('''insert into Users (cn, name, sAMAAccontName, servicePrincipalName, description) values (?,?,?,?,?)''', 
                        (cn, name,sam,spn,description))
        return
    
    def add_computer_to_db(self, entry):
        cursor = self.conn.cursor()
        hostname = str(entry['dNSHostName']) if 'dNSHostName' in entry else ''
        sitecode = ''
        signing = ''
        siteserver = ''
        mp = ''
        dp = ''
        wsus = ''
        mssql = ''
        if hostname:
            self.servers.append(str(hostname).lower())
        cursor.execute('''insert into Computers (Hostname, SiteCode, SigningStatus, SiteServer, ManagementPoint, DistributionPoint, WSUS, MSSQL) values (?,?,?,?,?,?,?,?)''', 
                        (hostname, sitecode, signing, siteserver, mp, dp, wsus, mssql))
        self.conn.commit()
        return

    # if a group is discovered rip out all the servers
    def recursive_resolution(self, dn):
        dn = dn
        search_filter = f"(memberOf:1.2.840.113556.1.4.1941:={dn})"
        try:
            self.ldap_session.extend.standard.paged_search(self.search_base, 
                                                        search_filter, 
                                                        attributes="*", 
                                                        paged_size=500, 
                                                        generator=False)  
        except ldap3.core.exceptions.LDAPAttributeError as e:
            logger.debug(f'Error: {str(e)}')
        

        results = self.ldap_session.entries
        return results


    def results(self):
        total_servers = list(set(self.servers))
        logger.info(f"[*] Found {len(total_servers)} total potential site servers.")
        if self.debug:
            for server in total_servers:
                logger.debug(f"[+] {server}")
        filename = "sccmhunter.log"
        printlog(total_servers, self.logs_dir, filename)


    def ldapsession(self):
        lmhash = ""
        nthash = ""
        if self.hashes:
            lmhash, nthash = self.hashes.split(':')
        if not (self.password or self.hashes or self.aes or self.no_pass):
                self.password = getpass("Password:")
        try:
            ldap_server, self.ldap_session = init_ldap_session(domain=self.domain, username=self.username, password=self.password, lmhash=lmhash, 
                                                               nthash=nthash, kerberos=self.kerberos, domain_controller=self.dc_ip, 
                                                               aesKey=self.aes, hashes=self.hashes, ldaps=self.ldaps)
            logger.debug(f'[+] Bind successful {ldap_server}')
        except ldap3.core.exceptions.LDAPSocketOpenError as e: 
            if 'invalid server address' in str(e):
                logger.info(f'Invalid server address - {self.domain}')
            else:
                logger.info('Error connecting to LDAP server')
                print()
                logger.info(e)
            exit()
        except ldap3.core.exceptions.LDAPBindError as e:
            logger.info(f'Error: {str(e)}')
            exit()



    def sid_resolver(self, sids):
        for sid in sids:
            search_filter ="(objectSid={})".format(sid)
            self.ldap_session.extend.standard.paged_search(self.search_base, 
                                                           search_filter,
                                                           attributes="*",
                                                           paged_size=500, 
                                                           generator=False)
            try:
                for entry in self.ldap_session.entries:
                    if (entry['sAMAccounttype']) == 268435456:                      
                        for member in entry['member']:
                            member = escape_filter_chars(member)
                            search_filter = f"(distinguishedName={member})"
                            self.ldap_session.extend.standard.paged_search(self.search_base, 
                                                                        search_filter, 
                                                                        attributes="*", 
                                                                        paged_size=500, 
                                                                        generator=False)
                            for entry in self.ldap_session.entries:
                                sid = entry['objectSid']
                                self.sid_resolver(sid)
                    if (entry['sAMAccountType']) == 805306369:       
                        dnsname = entry['dNSHostName']
                        if dnsname not in self.servers:
                            self.servers.append(str(dnsname).lower())
                        self.resolved_sids.append(str(dnsname))

            except ldap3.core.exceptions.LDAPKeyError as e:
                logger.debug(e)
            except Exception as e:
                logger.info(e)

    def ace_parser(self, descriptor):
        sids = []
        for ace in descriptor.dacl.aces:
            if ace["TypeName"] == "ACCESS_ALLOWED_ACE":
                ace = ace["Ace"]
                sid = ace["Sid"].formatCanonical()
                mask = ace["Mask"]
                fullcontrol = 0xf01ff
                if mask.hasPriv(fullcontrol):
                    sids.append(sid)
        self.sid_resolver(sids)

    def save_csv(self, users, computers, groups):
        user_fields =  ["cn","sAMAccountName", "servicePrincipalName", "description"]
        computer_fields = ["cn", "sAMAccountName", "dNSHostName", "description"]
        group_fields = ["cn", "name", "sAMAccountName", "member", "description"]
        if users:
            with open(f'{self.logs_dir}/csvs/users.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=user_fields)
                writer.writeheader()
                writer.writerows(users)
            f.close()
        if computers:
            with open(f'{self.logs_dir}/csvs/computers.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=computer_fields)
                writer.writeheader()
                writer.writerows(computers)
            f.close()
        if groups:
            with open(f'{self.logs_dir}/csvs/groups.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=group_fields)
                writer.writeheader()
                writer.writerows(groups)
            f.close()
        
        if self.debug:
            self.print_table()
        
    
    def print_table(self):
        logs = ["users.csv", "computers.csv", "groups.csv"]
        try:
            for log in logs:
                df = pd.read_csv(f"{self.logs_dir}/csvs/{log}").fillna("None")
                if df.any:
                    logger.info("[*] Showing {} table.".format(log.split(".")[0].upper()))
                logger.debug(tabulate(df, headers = 'keys', tablefmt = 'grid'))
        except:
            logger.info(f"[-] {log} file not found.")