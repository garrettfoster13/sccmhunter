from lib.logger import logger
from tabulate import tabulate
import pandas as dp
import sqlite3


class SHOW:

    def __init__(self, users=False, computers=False, groups=False, creds=False, all=False,logs_dir=None,site_servers=False, mps=False,
                 site_dbs=False, csv=False, js=False, debug=False):
        self.users = users
        self.computers = computers
        self.groups = groups
        self.creds = creds
        self.all = all
        self.site_servers = site_servers
        self.site_dbs = site_dbs
        self.management_points = mps
        self.logs_dir = logs_dir
        self.debug = debug
        self.database = f"{logs_dir}/db/find.db"
        self.conn = sqlite3.connect(self.database, check_same_thread=False)
        self.csv = csv
        self.json = js

    def _show_table(self, title, table, query, basename):
        cur = self.conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,))
        if cur.fetchone() is None:
            logger.info(f"[-] No {table} table in the database yet.")
            return
        logger.info(f"[+] Showing {title} Table")
        tb = dp.read_sql(query, self.conn).fillna('')
        logger.info(tabulate(tb, showindex=False, headers=tb.columns, tablefmt='grid'))
        if self.csv:
            tb.to_csv(f"{self.logs_dir}/csvs/{basename}.csv", encoding='utf-8')
        if self.json:
            tb.to_json(f"{self.logs_dir}/json/{basename}.json")

    def run(self):
        if self.site_servers or self.all:
            self._show_table("SiteServers", "SiteServers", "SELECT * FROM SiteServers WHERE Hostname IS NOT 'Unknown'", "siteservers")
        if self.management_points or self.all:
            self._show_table("ManagementPoints", "ManagementPoints", "SELECT * FROM ManagementPoints WHERE Hostname IS NOT 'Unknown'", "mps")
        if self.users or self.all:
            self._show_table("USERS", "Users", "SELECT * FROM Users", "users")
        if self.groups or self.all:
            self._show_table("GROUPS", "Groups", "SELECT * FROM Groups", "groups")
        if self.creds:
            self._show_table("Credentials", "Creds", "SELECT * FROM Creds", "creds")
        if self.computers or self.all:
            self._show_table("COMPUTERS", "Computers", "SELECT * FROM Computers", "computers")
        if self.site_dbs or self.all:
            self._show_table("SiteDatabases", "SiteDatabases", "SELECT * FROM SiteDatabases", "dbs")
        if self.csv:
            logger.info(f"[*] CSV files saved to {self.logs_dir}/csvs/")
        if self.json:
            logger.info(f"[*] JSON files saved to {self.logs_dir}/json/")


