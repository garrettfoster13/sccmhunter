# fix debug output, not seeing enough info "or any info"

from impacket.smbconnection import SMBConnection, SessionError
from lib.logger import logger, printlog
from requests.exceptions import RequestException
from tabulate import tabulate
from getpass import getpass
import ntpath
import os
import pandas as dp
import requests
import socket
import sqlite3

class SMB:
    
    def __init__(self, username=None, password=None, domain=None, target_dom=None, 
                    dc_ip=None,ldaps=False, kerberos=False, no_pass=False, hashes=None, 
                    aes=None, debug=False, save=False,
                    logs_dir=None):
        self.username = username
        self.password = password
        self.domain = domain
        self.target_dom = target_dom
        self.dc_ip = dc_ip
        self.ldaps = ldaps
        self.kerberos = kerberos
        self.no_pass = no_pass
        self.aes = aes
        self.save = save
        self.logs_dir = logs_dir
        self.debug = debug
        self.ldap_session = None
        self.search_base = None
        self.test_array = []
        self.hashes=hashes
        self.lmhash = ""
        self.nthash = ""
        if self.hashes:
            self.lmhash, self.nthash = self.hashes.split(':')
        self.database = f"{logs_dir}/db/find.db"
        self.conn = sqlite3.connect(self.database, check_same_thread=False)

    def run(self):
        #TODO add check to be sure FIND module was run
        self.check_siteservers()
        self.check_managementpoints()
        self.check_distributionpoints()
        self.check_computers()
        self.conn.close()


    #treat all computers with full control as siteservers and active
    #if default file shares are missing implies the use of high availability
    #which means it's possibly a passive site server that still retains the same
    #privileges
    def check_siteservers(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT Hostname FROM SiteServers WHERE Hostname IS NOT 'Unknown'")
        hostnames = cursor.fetchall()
        cursor.execute("SELECT * FROM CAS")
        cas = cursor.fetchall()
        if hostnames:
            logger.info (f"Profiling {len(hostnames)} site servers.")
            for i in hostnames:
                hostname = (i[0])
                cas_sitecode = False
                #only enumerate if the host is reachable
                conn = self.smb_connection(hostname)
                if conn:
                    signing, site_code, siteserv, distp, wsus, wdspxe, sccmpxe = self.smb_hunter(hostname, conn)
                    #check if mssql is self hosted
                    mssql = self.mssql_check(hostname)
                    #check for SMS provider roles
                    provider = self.provider_check(hostname)
                    #check if fileshares are on 
                    if siteserv:
                        status = "Active" 
                    else:
                        status = "Passive"

                    for i in cas:
                        if site_code in i:
                            cas_sitecode = True

                    cursor.execute(f'''Update SiteServers SET SiteCode=?, CAS=?, SigningStatus=?, SiteServer=?, SMSProvider=?, Config=?, MSSQL=? WHERE Hostname=?''',
                                (str(site_code), str(cas_sitecode), str(signing), "True", str(provider), str(status), str(mssql), hostname))
                else:
                    cursor.execute(f'''Update SiteServers SET SiteCode=?, CAS=?, SigningStatus=?, SiteServer=?, Config=?, MSSQL=? WHERE Hostname=?''',
                                ("Connection Failed", "", "", "True", "", "", hostname))

                self.conn.commit()
            logger.info("[+] Finished profiling Site Servers.")
            cursor.close()
            tb_ss = dp.read_sql("SELECT * FROM SiteServers WHERE Hostname IS NOT 'Unknown' ", self.conn)
            logger.info(tabulate(tb_ss, showindex=False, headers=tb_ss.columns, tablefmt='grid'))
        else:
            logger.info("[-] No SiteServers found in database.")
        return

    #check for signing status on management points
    def check_managementpoints(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT Hostname FROM ManagementPoints WHERE Hostname IS NOT 'Unknown'")
        hostnames = cursor.fetchall()
                #logger.info(f"Profling {len(cas)} site servers.")
        if hostnames:
            logger.info (f"Profiling {len(hostnames)} management points.")
            for i in hostnames:
                hostname = i[0]
                conn = self.smb_connection(hostname)
                if conn:
                    signing, site_code, siteserv, distp, wsus, wdspxe, sccmpxe = self.smb_hunter(hostname, conn)
                    cursor.execute(f'''Update ManagementPoints SET SigningStatus=? WHERE Hostname=?''',
                                (str(signing), hostname))
                self.conn.commit()

            logger.info("[+] Finished profiling Management Points.")
            cursor.close()
            tb_mp = dp.read_sql("SELECT * FROM ManagementPoints WHERE Hostname IS NOT 'Unknown' ", self.conn)
            logger.info(tabulate(tb_mp, showindex=False, headers=tb_mp.columns, tablefmt='grid'))
            return
        else:
            logger.info("[-] No Management Points found in database.")

    def check_distributionpoints(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT Hostname FROM PXEDistributionPoints WHERE Hostname IS NOT 'Unknown'")
        hostnames = cursor.fetchall()
        if hostnames:
            logger.info (f"Profiling {len(hostnames)} distribution points.")
            for i in hostnames:
                hostname = i[0]
                conn = self.smb_connection(hostname)
                if conn:
                    signing, site_code, siteserv, distp, wsus, wdspxe, sccmpxe = self.smb_hunter(hostname, conn)
                    #Hostname, SigningStatus, SCCM, WDS
                    cursor.execute(f'''Update PXEDistributionPoints SET SigningStatus=?, SCCM=?, WDS=? WHERE Hostname=?''',
                                (str(signing), str(sccmpxe), str(wdspxe), hostname))
                self.conn.commit()

            logger.info("[+] Finished profiling Distribution Points.")
            cursor.close()
            tb_dp = dp.read_sql("SELECT * FROM PXEDistributionPoints WHERE Hostname IS NOT 'Unknown' ", self.conn)
            logger.info(tabulate(tb_dp, showindex=False, headers=tb_dp.columns, tablefmt='grid'))
            return
        else:
            logger.info("[-] No Management Points found in database.")
    
    #read from computers table created from strings check in LDAP module
    def check_computers(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT Hostname FROM Computers WHERE Hostname IS NOT 'Unknown'")
        hostnames = cursor.fetchall()
        if hostnames:
            logger.info (f"Profiling {len(hostnames)} computers.")
            for i in hostnames:
                hostname = i[0]
                conn = self.smb_connection(hostname)
                if conn:
                    mssql = self.mssql_check(hostname)
                    mp = self.http_check(hostname)
                    provider = self.provider_check(hostname)
                    signing, site_code, siteserv, distp, wsus, wdspxe, sccmpxe = self.smb_hunter(hostname, conn)
                    if site_code == 'None':
                        try:
                            cursor.execute(f"SELECT SiteCode FROM ManagementPoints WHERE Hostname IS '{hostname}'")
                            result = cursor.fetchall()
                            if not result:
                                site_code = 'None'
                            else:
                                site_code = result[0][0]
                        except:
                            pass
                    cursor.execute(f'''Update Computers SET SiteCode=?, SigningStatus=?, SiteServer=?, ManagementPoint=?, DistributionPoint=?, SMSProvider=?, WSUS=?, MSSQL=? WHERE Hostname=?''',
                                (str(site_code), str(signing), str(siteserv), str(mp), str(distp), str(provider), str(wsus), str(mssql), hostname))
                self.conn.commit()
            logger.info("[+] Finished profiling all discovered computers.")
            cursor.close()
            tb_ss = dp.read_sql("SELECT * FROM Computers WHERE Hostname IS NOT 'Unknown' ", self.conn)
            logger.info(tabulate(tb_ss, showindex=False, headers=tb_ss.columns, tablefmt='grid'))
            return
        else:
            logger.info("[-] No computers found in database.")
    
    def smb_connection(self, server):
        try:
            if not (self.password or self.hashes or self.aes or self.no_pass):
                self.password = getpass("Password:")
            timeout = 10
            conn = SMBConnection(server, server, None, timeout=timeout)
            if self.kerberos:
                conn.kerberosLogin(user=self.username, password=self.password, domain=self.domain, kdcHost=self.dc_ip)
            else:
                conn.login(user=self.username, password=self.password, domain=self.domain, lmhash=self.lmhash, nthash=self.nthash)
            logger.debug(f"[+] Connected to smb://{server}:445")
            return conn
        except socket.error:
            logger.debug(f"[-] Error connecting to smb://{server}:445")
            return
        except Exception as e:
            logger.info(f"[-] {e}")
            return

    #profile remote hosts based on default file shares configured on particular roles
    def smb_hunter(self, server, conn):
        pxe_boot_servers = []
        try:
            site_code = 'None'
            siteserv = False
            distp = False
            wsus = False
            wdspxe = False
            sccmpxe = False

            signing = conn.isSigningRequired()
            shares = conn.listShares()
            sharenames = [share['shi1_netname'][:-1] for share in shares]
            remarks = [share['shi1_remark'][:-1] for share in shares]
            shares_dict = dict(zip(sharenames, remarks)) 

            if "SMS_SITE" in shares_dict:
                try:
                    remark = shares_dict.get('SMS_DP$', '')  
                    if 'ConfigMgr Site Server' in remark:
                        siteserv = True
                    sc = shares_dict.get("SMS_SITE", '')
                    if 'SMS Site' in sc:
                        site_code = (sc.split(" ")[2])
                except:
                    siteserv = False
            if "SMS_DP$" in shares_dict:
                try:
                    remark = shares_dict.get("SMS_DP$", '')
                    if "SMS Site" in remark:
                        distp = True
                        site_code = (remark.split(" ")[2])
                except:
                    distp = False
            if "REMINST" in shares_dict:
                #list REMINST contents to check if the SMSTemp dir actually exists
                remark = shares_dict.get("REMINST", '')
                if "Windows Deployment Services Share" in remark:
                    wdspxe = True
                if "RemoteInstallation" in remark:
                    sccmpxe = True
                check = conn.listPath(shareName="REMINST", path="//*")
                for i in check:
                    if i.get_longname() == "SMSTemp":
                        pxe_boot_servers.append(server)

            if "WsusContent" in shares_dict:
                wsus = True


        
            if pxe_boot_servers:
                self.smb_spider(conn, pxe_boot_servers)
            return signing, site_code, siteserv, distp, wsus, wdspxe, sccmpxe
        except socket.error:
            logger.info(socket.error)
            return
        except Exception as e:
            logger.info(f"[-] {e}")
            return

    #if a distribution point is found with this directory
    #spider and search for pxeboot variables files
    def smb_spider(self, conn, targets):
        vars_files = []
        downloaded = []
        timeout = 10
        for target in targets:
            try:
                logger.info(f'[*] Searching {target} for PXEBoot variables files.')
                conn = SMBConnection(target, target, None, timeout=timeout)
                if self.kerberos:
                    conn.kerberosLogin(user=self.username, password=self.password, domain=self.domain, kdcHost=self.dc_ip)
                else:
                    conn.login(user=self.username, password=self.password, domain=self.domain, lmhash=self.lmhash, nthash=self.nthash)
                for shared_file in conn.listPath(shareName="REMINST", path="SMSTemp//*"):
                    if shared_file.get_longname().endswith('.var'):
                        # store full path for easy reporting
                        full_path = (f"\\\\{target}\\REMINST\\SMSTemp\\{shared_file.get_longname()}")
                        vars_files.append(full_path)
                        logger.debug(f"[+] Found {full_path}")
                        if self.save:
                            file_name = shared_file.get_longname()
                            fh = open(ntpath.basename(file_name), 'wb')
                            path = f"SMSTemp//{file_name}"
                            try:
                                conn.getFile(shareName="REMINST",pathName = path, callback=fh.write)
                                downloaded.append(file_name)
                            except Exception as e:
                                logger.info(f"[-] {e}")
            except Exception as e:
                logger.debug(e)
        conn.logoff()
        
        #these logs should stay
        if len(downloaded) > 0:
            logger.info("[+] Variables files downloaded!")
            for i in (downloaded):
                os.replace(f'{os.getcwd()}/{i}', f'{self.logs_dir}/loot/{i}')
        if vars_files:
            filename = "smbhunter.log"
            printlog(vars_files, self.logs_dir, filename)
        

#check if the target host is running MSSQL
#intention here is to help find the site database location or at least narrow it down    
    def mssql_check(self, server):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((f'{server}', 1433))
            if sock:
                return True
        except Exception as e:
            logger.debug(f"[-] {e}")
        return False
    
#check if the target host is hosting the SMS_MP directory
#intention here is to return whether the host has the Management Point role
    def http_check(self, server):
        try:
            endpoint = f"http://{server}/ccm_system_windowsauth/"
            r = requests.request("GET",
                                endpoint,
                                verify=False)
            if r.status_code == 401:
                return True
            
            endpoint = f"https://{server}/ccm_system_windowsauth/"
            r = requests.request("GET",
                                endpoint,
                                verify=False)
            if r.status_code == 401:
                return True
            else:
                return False
        except RequestException as e:
            logger.debug(e)
            return False
        except Exception as e:
            logger.debug("An unknown error occurred")
            logger.debug(e)

#check if the target host is hosting the adminservice api 
#intention here is to return whether the host is hosting the SMS 
#Provider role
    def provider_check(self, server):
        try:
            endpoint = f"https://{server}/adminservice/wmi/"
            r = requests.request("GET",
                                endpoint,
                                verify=False)
            if r.status_code == 401:
                return True
            else:
                return False
        except RequestException as e:
            logger.debug(e)
            return False
        except Exception as e:
            logger.debug("An unknown error occurred")
            logger.debug(e)
        return

    def printlog(self, servers):
        filename = (f'{self.logs_dir}/smbhunter.log')
        logger.info(f'[+] Results saved to {filename}')
        for server in servers:
            with open(filename, 'a') as f:
                f.write("{}\n".format(server))
                f.close

