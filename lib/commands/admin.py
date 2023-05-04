import typer
from lib.attacks.admin import ADMINSERVICE
from lib.logger import init_logger

app = typer.Typer()
COMMAND_NAME = 'admin'
HELP = 'Collect and store data from AdminService API.  Note: this has been tested in a lab environment only. Use at your own risk.'

@app.callback(no_args_is_help=True, invoke_without_command=True)

def main(
    username        : str   = typer.Option(None, "-u",  help="Username"),
    password        : str   = typer.Option(None, '-p',  help="Password"),
    ip              : str   = typer.Option(None, '-ip',  help = "IP address or hostname of site server"),
    hashes          : str   = typer.Option(None, "-hashes",metavar="LMHASH:NTHASH", help="LM and NT hashes, format is LMHASH:NTHASH"),
    debug           : bool  = typer.Option(False, '-debug',help='Enable Verbose Logging'),
):



    logs_dir = init_logger(debug)
    adminhunter = ADMINSERVICE(username=username, password=password, ip=ip, hashes=hashes, debug=debug, logs_dir=logs_dir)
    adminhunter.run()