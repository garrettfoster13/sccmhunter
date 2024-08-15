from getpass import getpass
from ldap3.protocol.formatters.formatters import format_sid
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from ldap3.utils.conv import escape_filter_chars
from lib.ldap import init_ldap_session, get_dn
from lib.logger import logger
from tabulate import tabulate
import json
import ldap3
import os
import pandas as dp
import sqlite3


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
            logger.debug("[*] Database ready.")
            return True
        
    def validate_tables(self):
        table_names = ["CAS", "SiteServers", "ManagementPoints", "DistributionPoints", "Users", "Groups", "Computers", "Creds"]
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
        try:
            self.conn.execute('''CREATE TABLE CAS(SiteCode)''')
            self.conn.execute('''CREATE TABLE SiteServers(Hostname, SiteCode, CAS, SigningStatus, SiteServer, SMSProvider, Config, MSSQL)''')
            self.conn.execute('''CREATE TABLE ManagementPoints(Hostname, SiteCode, SigningStatus)''')
            self.conn.execute('''CREATE TABLE PXEDistributionPoints(Hostname, SigningStatus, SCCM, WDS)''')
            self.conn.execute('''CREATE TABLE Users(cn, name, sAMAAccontName, servicePrincipalName, description)''')
            self.conn.execute('''CREATE TABLE Groups(cn, name, sAMAAccontName, member, description)''')
            self.conn.execute('''CREATE TABLE Computers(Hostname, SiteCode, SigningStatus, SiteServer, ManagementPoint, DistributionPoint, SMSProvider, WSUS, MSSQL)''')
            self.conn.execute('''CREATE TABLE Creds(Username, Password, Source)''')
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
                dc_ip=None, resolve=False, ldaps=False, kerberos=False, no_pass=False, hashes=None, 
                aes=None, debug=False, logs_dir = None, all_computers=False):
        self.username = username
        self.password= password
        self.domain = domain
        self.target_dom = target_dom
        self.dc_ip = dc_ip
        self.resolve = resolve
        self.ldaps = ldaps
        self.kerberos = kerberos
        self.no_pass = no_pass
        self.hashes=hashes
        self.aes = aes
        self.debug = debug
        self.ldap_session = None
        self.search_base = None
        self.logs_dir = logs_dir
        self.controls = ldap3.protocol.microsoft.security_descriptor_control(sdflags=0x07)
        self.database = f"{logs_dir}/db/find.db"
        if os.path.exists(self.database):
            os.remove(self.database)
        self.conn = sqlite3.connect(self.database, check_same_thread=False)
        self.resolved_sids = []
        self.site_codes= []
        self.mp_sitecodes = []
        self.all_computers = all_computers

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
        #check for AD extension info
        self.check_schema()
        #check for potential DPs
        self.check_dps()
        #if they're using DNS only: thoughts and prayers
        self.check_strings()

        if self.all_computers:
            self.check_all_computers()
        
        if self.debug:
            self.results()
        self.conn.close()

    def check_schema(self):
        # Query the ACL Of the System Management container for FULL CONTROL permissions. This container
        # is created during optional extension of the Active Directory schema to allow site servers to publish 
        # to LDAP.
        logger.info(f'[*] Checking for System Management Container.')
        try:
            self.ldap_session.extend.standard.paged_search(self.search_base, 
                                                        search_filter=f"(distinguishedName=CN=System Management,CN=System,{self.search_base})", 
                                                        attributes="nTSecurityDescriptor", 
                                                        controls=self.controls,
                                                        paged_size=500, 
                                                        generator=False)
            #parse DACL
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
            #save results to DB
            if self.resolved_sids:
                cursor = self.conn.cursor()
                for result in set(self.resolved_sids):
                    print(type(result))
                    cursor.execute(f'''insert into SiteServers (Hostname, SiteCode, CAS, SigningStatus, SiteServer, Config, MSSQL) values (?,?,?,?,?,?,?)''',
                                (result, '', '', '', 'True', '', ''))
                    self.add_computer_to_db(result) 
                    self.conn.commit()
                cursor.execute('''SELECT COUNT (Hostname) FROM SiteServers''')
                count = cursor.fetchone()[0]
                logger.info(f'[+] Found {count} computers with Full Control ACE')
                cursor.close()
                #since container was found, check for management points
                self.check_mps()
            else:
                logger.info("[-] System Management Container not found.")
        except ldap3.core.exceptions.LDAPAttributeError as e:
            logger.info("[-] Did not find System Management Container")
            return
        except Exception as e:
            raise e

                    
                    
    def check_sites(self):
        try:
            self.ldap_session.extend.standard.paged_search(self.search_base, 
                                                search_filter="(objectclass=mssmssite)", 
                                                attributes="mSSMSSiteCode", 
                                                controls=self.controls,
                                                paged_size=500, 
                                                generator=False)
            if self.ldap_session.entries:
                for entry in self.ldap_session.entries:
                    sitecode = entry['msSMSSiteCode']
                    self.site_codes.append(sitecode)
                cas = [item for item in self.site_codes if item not in self.mp_sitecodes]
                if cas:
                    for sitecode in cas:
                        cursor = self.conn.cursor()
                        cursor.execute(f'''insert into CAS (SiteCode) values (?)''', (sitecode))

                
        except ldap3.core.exceptions.LDAPAttributeError as e:
            logger.info("[-] Did not find mSMSSite objectclass")
            return
        except Exception as e:
            logger.info(e)

    

    def check_mps(self):
        # Now query for the mssmsmanagementpoint object class. If schema exists there should be at least one.
        # Add to the site servers array // this might be redundant if we're querying for them specifically
        logger.info(f'[*] Querying LDAP for published Sites and Management Points')
        cursor = self.conn.cursor()
        try:
            self.ldap_session.extend.standard.paged_search(self.search_base, 
                                                        "(objectclass=mssmsmanagementpoint)", 
                                                        attributes="*", 
                                                        controls=self.controls, 
                                                        paged_size=500, 
                                                        generator=False)  
            if self.ldap_session.entries:
                logger.info(f"[+] Found {len(self.ldap_session.entries)} Management Points in LDAP.")
                for entry in self.ldap_session.entries:
                    hostname =  str(entry['dNSHostname']).lower()
                    sitecode = str(entry['msSMSSitecode'])
                    self.mp_sitecodes.append(sitecode)
                    cursor.execute(f'''insert into ManagementPoints (Hostname, SiteCode, SigningStatus) values (?,?,?)''',
                                (hostname, sitecode, ''))
                    if hostname:
                        self.add_computer_to_db(hostname) 
                    self.conn.commit()
            cursor.close()
            self.check_sites()

        except ldap3.core.exceptions.LDAPObjectClassError as e:
            logger.info(f'[-] Could not find any Management Points published in LDAP')


    def check_dps(self):
        #query for PXE enabled distribution points that are using Windows Deployment Services
        #if the DP is using WDS a child intellimirror-scp class will be published under the computer object
        #find all cases, parse the DN, then resolve the DN's hostname
        logger.info(f'[*] Querying LDAP for potential PXE enabled distribution points')
        cursor = self.conn.cursor()
        potential_dps = []
        try:
            self.ldap_session.extend.standard.paged_search(self.search_base, 
                                                        "(cn=*-Remote-Installation-Services)", 
                                                        attributes="distinguishedName", 
                                                        controls=self.controls, 
                                                        paged_size=500, 
                                                        generator=False)  
            if self.ldap_session.entries:
                logger.info(f"[+] Found {len(self.ldap_session.entries)} potential Distribution Points in LDAP.")
                for entry in self.ldap_session.entries:
                    dn =  str(entry['distinguishedName'])
                    if dn:
                        trim = dn.find(",")
                        trimmed = dn[trim + 1:]
                        potential_dps.append(trimmed)

        except ldap3.core.exceptions.LDAPObjectClassError as e:
            logger.info(f'[-] Could not find any Distribution Points published in LDAP')
        if potential_dps:
            for dn in potential_dps:
                try:
                    self.ldap_session.extend.standard.paged_search(self.search_base, 
                                                                f"(distinguishedName={dn})", 
                                                                attributes="dNSHostName", 
                                                                controls=self.controls, 
                                                                paged_size=500, 
                                                                generator=False)  
                    if self.ldap_session.entries:
                        for entry in self.ldap_session.entries:
                            hostname =  str(entry['dNSHostname'])
                            cursor.execute(f'''insert into PXEDistributionPoints (Hostname, SigningStatus, SCCM, WDS) values (?,?,?,?)''',
                                (hostname, '', '' , ''))
                            if hostname:
                                self.add_computer_to_db(hostname)
                            self.conn.commit()
                    
                except ldap3.core.exceptions.LDAPObjectClassError as e:
                    logger.info(f'[-] Could not find any Distribution Points published in LDAP')
        cursor.close()

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
        except Exception as e:
            logger.info(f"Error {e}")
        
        if self.ldap_session.entries:
            logger.info(f"[+] Found {len(self.ldap_session.entries)} principals that contain the string 'SCCM' or 'MECM'.")
            for entry in self.ldap_session.entries:
                #TODO: should there be logic for OU members?
                try:
                    if 'sAMAccountType' in entry:
                        #add user to db
                        if (entry['sAMAccountType']) == 805306368:
                            self.add_user_to_db(entry)
                        #add computer to db
                        if (entry['sAMAccountType']) == 805306369:
                            hostname =  str(entry['dNSHostname'])
                            if hostname:
                                self.add_computer_to_db(hostname)
                        #add group to db and then resolve members
                        if (entry['sAMAccountType']) == 268435456:
                            self.add_group_to_db(entry)
                            if self.resolve:
                                dn = (entry['distinguishedname'])
                                results = self.recursive_resolution(dn)
                                for result in results:
                                    #add parsed results to DB
                                    if (result['sAMAccountType']) == 805306368:
                                        self.add_user_to_db(result)
                                    if (result['sAMAccountType']) == 805306369:
                                        hostname =  str(result['dNSHostname'])
                                        if hostname:
                                            self.add_computer_to_db(result)
                                    if (result['sAMAccountType']) == 268435456:
                                        self.add_group_to_db(result)
                except ldap3.core.exceptions.LDAPAttributeError as e:
                    logger.debug(f"[-] {e}")
                except ldap3.core.exceptions.LDAPKeyError as e:
                    logger.debug(f"[-] {e}")
        else:
            logger.info("[-] No results found.")

    def check_all_computers(self):
        # If user specifies the option, get every computer object via LDAP
        logger.info(f'[*] Querying LDAP for all computer objects')
        cursor = self.conn.cursor()
        try:
            self.ldap_session.extend.standard.paged_search(self.search_base, 
                                                        "(&(objectCategory=computer))", 
                                                        attributes="dNSHostName", 
                                                        controls=self.controls, 
                                                        paged_size=500, 
                                                        generator=False)  
            if self.ldap_session.entries:
                logger.info(f"[+] Found {len(self.ldap_session.entries)} computers in LDAP.")
                for entry in self.ldap_session.entries:
                    hostname =  str(entry['dNSHostname'])
                    if hostname:
                        self.add_computer_to_db(hostname)
                    self.conn.commit()
            cursor.close()

        except ldap3.core.exceptions.LDAPObjectClassError as e:
            logger.info(f'[-] Could not find any computer objects in LDAP')            

    #add entries to database, check if attributes exists on entry, check if row already exists, add if not
    def add_group_to_db(self,entry):
        cursor = self.conn.cursor()
        cn = str(entry['cn']) if 'cn' in entry else ''
        name = str(entry['name']) if 'name' in entry else ''
        sam = str(entry['sAMAccountName']) if 'sAMAccountName' in entry else ''
        member = str(entry['member']).replace("['", "").replace("']", "\n").replace("', '", "\n") if 'member' in entry else ''
        description = str(entry['description']) if 'description' in entry else ''
        cursor.execute('''select * from Groups where name = ?''', (name,))
        exists = cursor.fetchone()
        if exists:
            logger.debug(f"[*] Skipping already group: {name}")        
        if not exists:
            logger.debug(f"[+] Found group: {name}")
            cursor.execute('''insert into Groups (cn, name, sAMAAccontName, member, description) values (?,?,?,?,?)''', 
                        (cn, name,sam,member,description))
            self.conn.commit()
        return

    def add_user_to_db(self, entry):
        cursor = self.conn.cursor()
        cn = str(entry['cn']) if 'cn' in entry else ''
        name = str(entry['name']) if 'name' in entry else ''
        sam = str(entry['sAMAccountName']) if 'sAMAccountName' in entry else ''
        spn = str(entry['servicePrincipalName']).replace("['", "").replace("']", "\n").replace("', '", "\n") if 'servicePrincipalName' in entry else ''
        description = str(entry['description']) if 'description' in entry else ''
        cursor.execute('''select * from Users where name = ?''', (name,))
        exists = cursor.fetchone()
        if exists:
            logger.debug(f"[*] Skipping already known user: {name}")
        if not exists:
            logger.debug(f"[+] Found user: {name}")
            cursor.execute('''insert into Users (cn, name, sAMAAccontName, servicePrincipalName, description) values (?,?,?,?,?)''', 
                        (cn, name,sam,spn,description))
            self.conn.commit()
        return
    
    def add_computer_to_db(self, entry):
        cursor = self.conn.cursor()
        hostname = entry
        sitecode = ''
        signing = ''
        siteserver = ''
        mp = ''
        dp = ''
        wsus = ''
        mssql = ''
        cursor.execute('''select * from Computers where Hostname = ?''', (hostname,))
        exists = cursor.fetchone()
        if exists:
            logger.debug(f"[*] Skipping already known host: {hostname}")
        if not exists:
            logger.debug(f"[+] Found host: {hostname}")
            cursor.execute('''insert into Computers (Hostname, SiteCode, SigningStatus, SiteServer, ManagementPoint, DistributionPoint, WSUS, MSSQL) values (?,?,?,?,?,?,?,?)''', 
                        (hostname, sitecode, signing, siteserver, mp, dp, wsus, mssql))
            self.conn.commit()

        return

    #resolve all group members
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
            logger.info("Something went wrong. Use -debug to print a stack trace.")
            logger.debug(f'Error: {str(e)}')
        except Exception as e:
            logger.info("Something went wrong. Use -debug to print a stack trace.")
            logger.debug(f"[-] {e}")
        
        results = self.ldap_session.entries
        return results

    def results(self):
        tb_ss = dp.read_sql("SELECT * FROM SiteServers WHERE Hostname IS NOT 'Unknown' ", self.conn)
        tb_mp = dp.read_sql("SELECT * FROM ManagementPoints WHERE Hostname IS NOT 'Unknown' ", self.conn)
        tb_dp = dp.read_sql("SELECT * FROM PXEDistributionPoints WHERE Hostname IS NOT 'Unknown' ", self.conn)
        tb_c = dp.read_sql("SELECT * FROM Computers WHERE Hostname IS NOT 'Unknown' ", self.conn)
        tb_u = dp.read_sql("SELECT * FROM Users", self.conn)
        tb_g = dp.read_sql("SELECT * FROM Groups", self.conn)
        logger.info("Site Servers Table")
        logger.info(tabulate(tb_ss, showindex=False, headers=tb_ss.columns, tablefmt='grid'))
        logger.info("Management Points Table")
        logger.info(tabulate(tb_mp, showindex=False, headers=tb_mp.columns, tablefmt='grid'))
        logger.info("Potential PXE Distribution Points")
        logger.info(tabulate(tb_dp, showindex=False, headers=tb_dp.columns, tablefmt='grid'))
        logger.info('Computers Table')
        logger.info(tabulate(tb_c, showindex=False, headers=tb_c.columns, tablefmt='grid'))
        logger.info("Users Table")
        logger.info(tabulate(tb_u, showindex=False, headers=tb_u.columns, tablefmt='grid'))
        logger.info("Groups Table")
        logger.info(tabulate(tb_g, showindex=False, headers=tb_g.columns, tablefmt='grid'))

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

    def member_sid_resolver(self, member):
        sid = []
        member = escape_filter_chars(member)
        search_filter = f"(distinguishedName={member})"
        self.ldap_session.extend.standard.paged_search(self.search_base, 
                                                    search_filter, 
                                                    attributes="*", 
                                                    paged_size=500, 
                                                    generator=False)
        for entry in self.ldap_session.entries:
            json_entry = json.loads(entry.entry_to_json())
            attributes = json_entry['attributes'].keys()
            for attr in attributes:
                if attr == "objectSid":
                    sid.append(format_sid(entry[attr].value))
        self.sid_resolver(sid)


    def sid_resolver(self, sids):
        for sid in sids:
            search_filter = "(objectSid={})".format(sid)
            self.ldap_session.extend.standard.paged_search(self.search_base, 
                                                        search_filter,
                                                        attributes="*",
                                                        paged_size=500, 
                                                        generator=False)
            try:
                for entry in self.ldap_session.entries:

                    json_entry = json.loads(entry.entry_to_json())
                    attributes = json_entry['attributes'].keys()
                    for attr in attributes:
                        if (entry['sAMAccountType']) == "268435456" or 268435456:
                            if attr == 'member':
                                if type(entry[attr].value) is list:
                                    for member in entry['member'].value:
                                        self.member_sid_resolver(member)
                                if type(entry[attr].value) is str:
                                    member = entry[attr].value
                                    self.member_sid_resolver(member)

                        if entry['sAMAccountType'] == "805306369" or 805306369:
                            if attr == 'dNSHostName':
                                dnsname = entry['dNSHostName'].value  
                                self.resolved_sids.append(str(dnsname).lower())

            except ldap3.core.exceptions.LDAPKeyError as e:
                logger.debug(e)
            except Exception as e:
                logger.info(e)

    def ace_parser(self, descriptor):
        sids = []
        for ace in descriptor.dacl.aces:
            if ace["TypeName"] == "ACCESS_ALLOWED_ACE" or ace["TypeName"] == "ACCESS_ALLOWED_OBJECT_ACE":
                ace = ace["Ace"]
                sid = ace["Sid"].formatCanonical()
                mask = ace["Mask"]
                fullcontrol = 0xf01ff
                if mask.hasPriv(fullcontrol):
                    sids.append(sid)
        self.sid_resolver(sids)
