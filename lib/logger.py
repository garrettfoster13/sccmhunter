import logging
from rich.logging import RichHandler
from rich.console import Console
import os

console = Console()

FORMAT = "%(message)s"

OBJ_EXTRA_FMT = {
    "markup": True,
    "highlighter": False
}

logger = logging.getLogger(__name__)
logger.propagate = False

def prep_logs():
    home = os.path.expanduser('~')
    save_dir = f'{(home)}/.sccmhunter'
    logs_dir = f'{save_dir}/logs'
    loot_dir = f'{logs_dir}/loot'
    csv_dir = f'{logs_dir}/csvs'
    json_dir = f'{logs_dir}/json'
    db_dir = f'{logs_dir}/db'
    if not os.path.isdir(save_dir):
        logger.info("[!] First time use detected.")
        logger.info(f"[!] SCCMHunter data will be saved to {save_dir}")
        os.mkdir(save_dir)
    if not os.path.isdir(logs_dir):
        os.mkdir(logs_dir)
    if not os.path.isdir(loot_dir):
        os.mkdir(loot_dir)
    if not os.path.isdir(csv_dir):
        os.mkdir(csv_dir)
    if not os.path.isdir(json_dir):
        os.mkdir(json_dir)
    if not os.path.isdir(db_dir):
        os.mkdir(db_dir)
        with open(f'{db_dir}/sccmhunter.db', 'w') as fp:
            pass
    return logs_dir


def init_logger(debug):
    richHandler = RichHandler(omit_repeated_times=False, 
                              show_path=False, 
                              keywords=[], 
                              console=console)
    
    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)


    richHandler.setFormatter(logging.Formatter(FORMAT, datefmt='[%X]'))
    logger.addHandler(richHandler)
    logs_dir = prep_logs()
    return logs_dir


def printlog(servers, logs_dir, filename):
    logfile = f'{logs_dir}/{filename}'
    logger.info(f'[+] Results saved to {logfile}')
    with open(logfile, 'w') as f:
        for server in servers:
            if server is not None:
                f.write("{}\n".format(server))
                f.close