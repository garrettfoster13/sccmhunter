from lib.logger import logger
from tabulate import tabulate
import pandas as pd


class SHOW:

    def __init__(self, users=False, computers=False, groups=False, smb=False, all=False,logs_dir=None, debug=False):
        self.users = users
        self.computers = computers
        self.groups = groups
        self.smb = smb
        self.all= all
        self.logs_dir = logs_dir
        self.debug = debug


    def run(self):
        csv_dir = f'{self.logs_dir}/csvs'
        if self.users or self.all:
            logger.info("[+] Showing USERS Table")
            df = pd.read_csv(f"{csv_dir}/users.csv")
            logger.info(tabulate(df, headers = 'keys', tablefmt = 'grid'))
        if self.groups or self.all:
            logger.info("[+] Showing GROUPS Table")
            df = pd.read_csv(f"{csv_dir}/groups.csv")
            logger.info(tabulate(df, headers = 'keys', tablefmt = 'grid'))
        if self.computers or self.all:
            logger.info("[+] Showing COMPUTERS Table")
            df = pd.read_csv(f"{csv_dir}/computers.csv")
            logger.info(tabulate(df, headers = 'keys', tablefmt = 'grid'))
        if self.smb or self.all:
            logger.info("[+] SMB Results Table")
            df = pd.read_csv(f"{csv_dir}/smbhunter.csv")
            logger.info(tabulate(df, headers = 'keys', tablefmt = 'grid'))    
        
