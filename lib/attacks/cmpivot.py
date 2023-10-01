import cmd2
import pandas as dp
import requests
import traceback
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
    SA = "Situational Awareness Commands"
    PE = "PostEx Commands"
    DB = "Database Commands"
    IN = "Interface Commands"
    hidden = ["alias", "help", "macro", "run_pyscript", "set", "shortcuts", "edit", "history", "quit", "run_script", "shell", "_relative_run_script", "eof"]

    def __init__(self, username, password, target, logs_dir):
        #initialize plugins
        self.pivot = CMPIVOT(username=username, password=password, target = target, logs_dir = logs_dir)
        self.script = SMSSCRIPTS(username=username, password=password, target = target, logs_dir = logs_dir,)
        self.backdoor = BACKDOOR(username=username, password=password, target = target, logs_dir = logs_dir)
        
        #initialize cmd
        super().__init__(allow_cli_args=False)
        self.hidden_commands = self.hidden
        self.username = username
        self.password = password
        self.target = target
        self.logs_dir = logs_dir
        self.headers = {'Content-Type': 'application/json; odata=verbose'} # add useragent? currently shows python useragent in logs
        self.intro = logger.info('[!] Enter help for extra shell commands')
        self.cwd = "C:\\"
        self.device = ""
        self.prompt = f"({self.device}) {self.cwd} >> "
        self.hostname = ""


# ############
# cmd2 Settings
# ############

    def emptyline(self):
        pass

    def postcmd(self, stop, arg):
        self.prompt = f"({self.device}) ({self.cwd}) >> "
        return stop
    
    # def check_device(self, device_id):
    #     _dbname = f"{self.logs_dir}/db/sccmhunter.db"
    #     conn = sqlite3.connect(_dbname, check_same_thread=False)

    @cmd2.with_category(IN)
    def do_interact(self, arg):
        """Target Device Code to Query              interact (device code)"""
        option = arg.split(' ')
        self.device = option[0]

    @cmd2.with_category(IN)
    def do_exit(self, arg):
        """Exit the console."""
        return True 
    
    @cmd2.with_category(SA)
    def do_cd(self, arg):
        """Change current working directory."""
        #path needs to end with \ or all file system queries will fail
        if not arg.endswith("\\"): 
            arg = arg + "\\"
        option = arg.split(' ')
        self.cwd = option[0]


# ############
# Database Section
# ############

    @cmd2.with_category(DB)
    def do_get(self, arg):
        """
Usage
get user [username]                     Get information about a specific user.
get device [machinename]                Get information about a specific device.
get puser [username]                    Show where target is a primary user.
get application [*] or [ID]          Show all or single app.
get collection [*] or [ID]            Show all or single collection.
get deployment [*] or [AssignmentName]  Show all or single deployment.
get lastlogon [username]                Show where target user last logged in."""
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

    @cmd2.with_category(SA)    
    def do_cat(self, arg):
        """Read file contents.                      cat (filename)"""
        option = arg.split(' ')
        filename = option[0]
        logger.info(f"Tasked SCCM to show {arg}")
        fullpath = self.cwd + filename
        self.script.cat(fullpath, device=self.device)
    
    @cmd2.with_category(PE)
    def do_script(self, arg):
        """Run script on target                     script (/path/to/script) """
        option = arg.split(' ')
        scriptpath = option[0]
        self.script.run(device=self.device, optional_target=scriptpath)

# ############
# CMPivot Backdoor Section
# Backdoor existing CMPivot script with your own
# ############
    
    @cmd2.with_category(PE)
    def do_backdoor(self, arg):
        """Backdoor CMPivot Script                  backdoor (/path/to/script) """
        logger.info("Tasked SCCM to backdoor CMPivot with provided script")
        check = input("IMPORTANT: Did you backup the script first? There is no going back without it. Y/N?")
        if check.lower() == "y":
            option = arg.split(' ')
            scriptpath = option[0]
            self.backdoor.run(option="backdoor", scriptpath=scriptpath)

        else:
            return
    @cmd2.with_category(PE)
    def do_restore(self, arg):
        """Restore original CMPivot Script"""
        logger.info("Tasked SCCM to restore the original CMPivot script.")
        option = arg.split(' ')
        self.backdoor.run(option="restore", scriptpath=None)

    @cmd2.with_category(PE)
    def do_backup(self, arg):
        """Backup original CMPivot Script"""
        logger.info("Tasked SCCM to backup the CMPivot script.")
        option = arg.split(' ')
        self.backdoor.run(option="backup", scriptpath=None)

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


    
                                                                                                                                                                                                                           
