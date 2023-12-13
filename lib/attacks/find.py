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



class DACLPARSE:

    def __init__(self):
        self.security_descriptor = SR_SECURITY_DESCRIPTOR()

    @property
    def dacl(self):
        return self.security_descriptor["Dacl"]
    
    @property
    def owner_sid(self):
        return self.security_descriptor['OwnerSid'] 


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


    def run(self):
        #bind to ldap
        if not self.ldap_session:
            self.ldapsession()

        # set search base to query
        if self.target_dom:
            self.search_base = get_dn(self.target_dom)
        else:
            self.search_base = get_dn(self.domain)

        self.check_schema()
        self.check_strings()

        if self.servers:
            self.results()

        
    def check_schema(self):
        # Query the ACL Of the System Management container for FULL CONTROL permissions. This container
        # is created during optional extension of the Active Directory schema to allow site servers to publish 
        # to LDAP.
        logger.info(f'[*] Checking for presence of System Management Container.')
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
                    #refactor: can this be crunched down? I don't think the json load is necessary
                    json_entry = json.loads(entry.entry_to_json())
                    attributes = json_entry['attributes'].keys()
                    dacl = DACLPARSE()
                    for attr in attributes:
                        secdesc = (entry[attr].value)
                        dacl.security_descriptor.fromString(secdesc)
                self.ace_parser(dacl)

            if len(self.servers) > 0:
                total_control = list(set(self.servers))
                if self.debug:
                    for hostname in total_control:
                        logger.debug(f'[+] Found {hostname} with Full Control Ace')
                logger.info(f'[+] Found {len(total_control)} computers with Full Control ACE')
                filename = "siteservers.log"
                printlog(total_control, self.logs_dir, filename)
                self.check_mps()
            else:
                logger.info("[-] System Management Container not found.")
        except ldap3.core.exceptions.LDAPAttributeError as e:
            logger.info("[-] Did not find System Management Container")
            return


    def check_mps(self):
        # Now query for the mssmsmanagementpoint object class. If schema exists there should be at least one.
        # Add to the site servers array // this might be redundant if we're querying for them specifically
        logger.info(f'[*] Querying LDAP for published Management Points')
        mps = []
        try:
            self.ldap_session.extend.standard.paged_search(self.search_base, 
                                                           "(objectclass=mssmsmanagementpoint)", 
                                                           attributes=["dNSHostName", "msSMSSiteCode"], 
                                                           controls=self.controls, 
                                                           paged_size=500, 
                                                           generator=False)  
            if self.ldap_session.entries:
                os.remove(f'{self.logs_dir}/mps.json')
                #output the number of objects found
                logger.info(f"[+] Found {len(self.ldap_session.entries)} Management Points in LDAP.")
                for entry in self.ldap_session.entries:
                    hostname =  entry['dNSHostname']
                    logger.debug(f"[+] Found Management Point: {hostname}")
                    self.servers.append(str(hostname).lower())
                    with open(f'{self.logs_dir}/mps.json', 'a') as f:
                        json.dump(entry.entry_to_json(), f, indent=None )
                json_entry = json.loads(entry.entry_to_json())
                print(json_entry)


        except ldap3.core.exceptions.LDAPObjectClassError as e:
            logger.info(f'[-] Could not find any Management Points published in LDAP')


    def check_strings(self):
        #now search for anything related to "SCCM" 
        _users = []
        _computers = []
        _groups = []
        yeet = '(|(samaccountname=*sccm*)(samaccountname=*mecm*)(description=*sccm*)(description=*mecm*)(name=*sccm*)(name=*mecm*))'
        logger.info("[*] Searching LDAP for anything containing the strings 'SCCM'or 'MECM'")
        try:
            self.ldap_session.extend.standard.paged_search(self.search_base, 
                                                           yeet, 
                                                           attributes="*", 
                                                           paged_size=500, 
                                                           generator=False)  
        except ldap3.core.exceptions.LDAPAttributeError as e:
            logger.info(f'Error: {str(e)}')
        
        
        if self.ldap_session.entries:
            logger.info(f"[+] Found {len(self.ldap_session.entries)} principals that contain the string 'SCCM' or 'MECM'.")
            for entry in self.ldap_session.entries:
                USER_DICT = {"cn": "", "sAMAccountName": "", "servicePrincipalName": "", "description": ""}
                COMPUTER_DICT = {"cn": "", "sAMAccountName": "", "dNSHostName": "", "description": ""}
                GROUP_DICT = {"cn": "", "name": "", "sAMAccountName": "", "member": "", "description": ""}
                #if a user
                try:
                    if (entry['sAMAccountType']) == 805306368:
                        for k, v in USER_DICT.items():
                            if k in entry:
                                USER_DICT[k] = str(entry[k].value)
                        _users.append(USER_DICT)
                    # if a computer
                    if (entry['sAMAccountType']) == 805306369:
                        for k, v in COMPUTER_DICT.items():
                            if k in entry:
                                COMPUTER_DICT[k] = str(entry[k].value)
                            # add to potential site servers array
                            dnshostname = entry["dNSHostName"]
                            if dnshostname:
                                self.servers.append(str(dnshostname).lower())
                        _computers.append(COMPUTER_DICT)
                    # #if a group
                    if (entry['sAMAccountType']) == 268435456:
                        for k, v in GROUP_DICT.items():
                            if k in entry:
                                GROUP_DICT[k] = str(entry[k].value)
                        dn = (entry['distinguishedname'])
                        self.recursive_resolution(dn)
                        _groups.append(GROUP_DICT)
                except ldap3.core.exceptions.LDAPAttributeError as e:
                    logger.debug(f"[-] {e}")
                except ldap3.core.exceptions.LDAPKeyError as e:
                    logger.debug(f"[-] {e}")
        else:
            logger.info("[-] No results found.")

        self.save_csv(_users, _computers, _groups)


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
            
            for i in self.ldap_session.entries:
                if (i['samaccounttype'] == 805306369):
                    self.servers.append(str(i['dnshostname']).lower())

    def sid_resolver(self, sids):
        resolved_sids = []
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
                        resolved_sids.append(dnsname)
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

    def save_json(self, users, computers, groups):
        if users:
            with open(f'{self.logs_dir}/csvs/users.json', 'w', newline='') as f:
                json.dump(users, f)


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