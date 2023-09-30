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
        self.attributes = ["dNSHostName", "nTSecurityDescriptor"]
        self.search_filter = "(objectclass=mssmsmanagementpoint)"
        self.servers = []
        self.resolvedowners = []
        self.samname= []
        self.users = []
        self.groups = []
        self.computers = []
        self.logs_dir = logs_dir
        self.controls = ldap3.protocol.microsoft.security_descriptor_control(sdflags=0x07)


    def run(self):

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
        
        # set search base to query
        if self.target_dom:
            self.search_base = get_dn(self.target_dom)
        else:
            self.search_base = get_dn(self.domain)

        # Query the ACL Of the System Management container for FULL CONTROL permissions. This container
        # is created during extension of the Active Directory schema to allow site servers to publish to LDAP.

        logger.debug(f'[*] Querying ACL of System Management Container')
        try:
            self.ldap_session.extend.standard.paged_search(self.search_base, 
                                                           search_filter="(cn=System Management)", 
                                                           attributes="nTSecurityDescriptor", 
                                                           controls=self.controls,
                                                           paged_size=500, 
                                                           generator=False)  
        except ldap3.core.exceptions.LDAPAttributeError as e:
            print()
            logger.info(f'Error: {str(e)}')
            exit()


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
        else:
            logger.info("[-] Did not find System Management Container")
        if len(self.samname) > 0:
            total_control = list(set(self.samname))
            logger.info(f'[+] Found {len(total_control)} computers with Full Control ACE')
        if self.debug:
            for sam in total_control:
                logger.debug(f'[+] Found {sam} with Full Control Ace')

        # Done with ACL now check what's been published to the container if it exists. CAS, primary servers
        # and secondary servers will appear here.

        logger.info(f'[*] Querying LDAP for published Management Points')
        container_servers = []
        container_owners = []
        try:
            controls = ldap3.protocol.microsoft.security_descriptor_control(sdflags=0x07)
            self.ldap_session.extend.standard.paged_search(self.search_base, self.search_filter, attributes=self.attributes, 
                                                           controls=controls, paged_size=500, generator=False)  
        except ldap3.core.exceptions.LDAPObjectClassError as e:
            logger.info(f'[-] Management Point Attribute not found')
            logger.info(f'[-] SCCM doesn\'t appear to be published in this domain.')
            exit()

        if self.ldap_session.entries:
            logger.info(f"[+] Found {len(self.ldap_session.entries)} site servers in LDAP.")
            for entry in self.ldap_session.entries:
                json_entry = json.loads(entry.entry_to_json())
                attributes = json_entry['attributes'].keys()
                dacl = DACLPARSE()
                
                secdesc = (entry['nTSecurityDescriptor'].value)
                dacl.security_descriptor.fromString(secdesc)
                ownersid = dacl.owner_sid.formatCanonical()
                container_owners.append(ownersid)

                hostname =  entry['dNSHostname']
                logger.debug(f"[+] Found Management Point: {hostname}")
                container_servers.append(str(hostname).lower())
        else:
            logger.info("[-] Did not find any published Management Points.")
        
        resolved_owners = self.sid_resolver(container_owners)
        for owner in resolved_owners:
            if owner not in self.servers:
                logger.debug(f"[+] Found container owner: {owner}")
                owner = str(owner).lower()
                self.servers.append(owner.lower())

        for server in container_servers:
            server = server.lower()
            if server not in self.servers:
                self.servers.append(server)

        #now search for anything related to "SCCM" and build a csv
        _users = []
        _computers = []
        _groups = []
        yeet = '(|(samaccountname=*sccm*)(samaccountname=*mecm*)(description=*sccm*)(description=*mecm*))'
        logger.info("[*] Searching LDAP for anything containing the strings 'SCCM'or 'MECM'")
        try:
            self.ldap_session.extend.standard.paged_search(self.search_base, 
                                                           yeet, 
                                                           attributes="*", 
                                                           paged_size=500, 
                                                           generator=False)  
        except ldap3.core.exceptions.LDAPAttributeError as e:
            print()
            logger.info(f'Error: {str(e)}')
        if self.ldap_session.entries:
            logger.debug(f"[+] Found {len(self.ldap_session.entries)} principals that contain the string 'SCCM' or 'MECM'.")
            for entry in self.ldap_session.entries:
                USER_DICT = {"cn": "", "sAMAccountName": "", "memberOf": "", "servicePrincipalName": "", "description": ""}
                COMPUTER_DICT = {"cn": "", "sAMAccountName": "", "dNSHostName": "", "memberOf": "", "description": ""}
                GROUP_DICT = {"cn": "", "name": "", "sAMAccountName": "", "member": "", "memberOf": "", "description": ""}
                #if a user
                try:
                    if (entry['sAMAccountType']) == 805306368:
                        for k, v in USER_DICT.items():
                            if k in entry:
                                USER_DICT[k] = str(entry[k].value)
                        for k, v in USER_DICT.items():
                            if k =='servicePrincipalName':
                                j = v.replace("['", "").replace("', '", "\n").replace("']", "")
                                USER_DICT[k] = j
                        _users.append(copy.deepcopy(USER_DICT))
                    # if a computer
                    if (entry['sAMAccountType']) == 805306369:
                        #COMPUTER_DICT = {"cn": "", "sAMAccountName": "None", "dNSHostName": "", "memberOf": "", "description": ""}
                            for k, v in COMPUTER_DICT.items():
                                if k in entry:
                                    COMPUTER_DICT[k] = str(entry[k].value)
                                #might as well add it to the results list for SMB scanning
                                dnshostname = entry["dNSHostName"]
                                if dnshostname and dnshostname not in self.servers:
                                    self.servers.append(str(dnshostname).lower())
                                #return
                            _computers.append(copy.deepcopy(COMPUTER_DICT))
                    #if a group
                    if (entry['sAMAccountType']) == 268435456:
                        for k, v in GROUP_DICT.items():
                            if k in entry:
                                GROUP_DICT[k] = str(entry[k].value)
                        for k, v in GROUP_DICT.items():
                            if k =='member':
                                #i should learn regex
                                j = v.replace("', '", "\n").replace("['", "").replace("']", "")
                                GROUP_DICT[k] = j
                        _groups.append(copy.deepcopy(GROUP_DICT))
                except ldap3.core.exceptions.LDAPAttributeError as e:
                    logger.debug(f"[-] {e}")
                except ldap3.core.exceptions.LDAPKeyError as e:
                    logger.debug(f"[-] {e}")
        else:
            logger.info("[-] No SCCM Servers found.")

        self.save_csv(_users, _computers, _groups)


        # show results
        total_servers = list(set(self.servers))
        logger.info(f"[*] Found {len(total_servers)} total potential site servers.")
        if self.debug:
            for server in total_servers:
                logger.debug(f"[+] {server}")

        # log results if we found anything
        if total_servers:
            filename = "sccmhunter.log"
            printlog(total_servers, self.logs_dir, filename)

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
                    # dig into groups
                    # could probably make this better
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
                        samname = (entry['sAMAccountName'][0])         
                        dnsname = entry['dNSHostName']
                        if dnsname not in self.servers:
                            self.servers.append(str(dnsname).lower())
                        self.samname.append(str(samname).lower())
                        resolved_sids.append(dnsname)
            except Exception as e:
                logger.info(e)
        return resolved_sids

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
        user_fields =  ["cn","sAMAccountName", "memberOf", "servicePrincipalName", "description"]
        computer_fields = ["cn", "sAMAccountName", "dNSHostName","memberOf", "description"]
        group_fields = ["cn", "name", "sAMAccountName", "member", "memberOf", "description"]
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