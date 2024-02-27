from lib.logger import logger
from tabulate import tabulate
import pandas as dp
import sqlite3


class SHOW:

    def __init__(self, users=False, computers=False, groups=False, creds=False, all=False,logs_dir=None,site_servers=False, mps=False,
                 csv=False, js=False, debug=False):
        self.users = users
        self.computers = computers
        self.groups = groups
        self.creds = creds
        self.all = all
        self.site_servers = site_servers
        self.management_points = mps
        self.logs_dir = logs_dir
        self.debug = debug
        self.database = f"{logs_dir}/db/find.db"
        self.conn = sqlite3.connect(self.database, check_same_thread=False)
        self.csv = csv
        self.json = js


    def run(self):
        if self.site_servers or self.all:
            logger.info("[+] Showing SiteServers Table")
            tb_ss = dp.read_sql("SELECT * FROM SiteServers WHERE Hostname IS NOT 'Unknown'", self.conn)
            logger.info(tabulate(tb_ss, showindex=False, headers=tb_ss.columns, tablefmt='grid'))
            if self.csv:
                tb_ss.to_csv(f"{self.logs_dir}/csvs/siteservers.csv", encoding='utf-8')
            if self.json:
                tb_ss.to_json(f"{self.logs_dir}/json/siteservers.json")
        if self.management_points or self.all:
            logger.info("[+] Showing ManagementPoints Table")
            tb_mp = dp.read_sql("SELECT * FROM ManagementPoints WHERE Hostname IS NOT 'Unknown'", self.conn)
            logger.info(tabulate(tb_mp, showindex=False, headers=tb_mp.columns, tablefmt='grid'))
            if self.csv:
                tb_mp.to_csv(f"{self.logs_dir}/csvs/mps.csv", encoding='utf-8')
            if self.json:
                tb_mp.to_json(f"{self.logs_dir}/json/mps.json")
        if self.users or self.all:
            logger.info("[+] Showing USERS Table")
            tb_u = dp.read_sql("SELECT * FROM Users", self.conn)
            logger.info(tabulate(tb_u, showindex=False, headers=tb_u.columns, tablefmt='grid'))
            if self.csv:
                tb_u.to_csv(f"{self.logs_dir}/csvs/users.csv", encoding='utf-8')
            if self.json:
                tb_u.to_json(f"{self.logs_dir}/json/users.json")
        if self.groups or self.all:
            logger.info("[+] Showing GROUPS Table")
            tb_gp = dp.read_sql("SELECT * FROM Groups", self.conn)
            logger.info(tabulate(tb_gp, showindex=False, headers=tb_gp.columns, tablefmt='grid'))
            if self.csv:
                tb_gp.to_csv(f"{self.logs_dir}/csvs/groups.csv", encoding='utf-8')
            if self.json:
                tb_gp.to_json(f"{self.logs_dir}/json/groups.json")
        if self.creds:
            logger.info("[+] Showing Crdentials Table")
            tb_gp = dp.read_sql("SELECT * FROM Creds", self.conn)
            logger.info(tabulate(tb_gp, showindex=False, headers=tb_gp.columns, tablefmt='grid'))
            if self.csv:
                tb_gp.to_csv(f"{self.logs_dir}/csvs/creds.csv", encoding='utf-8')
            if self.json:
                tb_gp.to_json(f"{self.logs_dir}/json/creds.json")
        if self.computers or self.all:
            logger.info("[+] Showing COMPUTERS Table")
            tb_c = dp.read_sql("SELECT * FROM Computers", self.conn)
            logger.info(tabulate(tb_c, showindex=False, headers=tb_c.columns, tablefmt='grid'))   
            if self.csv:
                tb_c.to_csv(f"{self.logs_dir}/csvs/computers.csv", encoding='utf-8')
            if self.json:
                tb_c.to_json(f"{self.logs_dir}/json/computers.json")
        if self.csv:
            logger.info(f"[*] CSV files saved to {self.logs_dir}/csvs/")
        if self.json:
            logger.info(f"[*] JSON files saved to {self.logs_dir}/json/")

        
