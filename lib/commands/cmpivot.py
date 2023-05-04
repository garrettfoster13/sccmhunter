import typer
from lib.attacks.cmpivot import CMPIVOT
from lib.logger import init_logger

app = typer.Typer()
COMMAND_NAME = 'pivot'
HELP = 'Run CMPivot commands on target devices through the AdminService API. Site Server Administrator rights required.'

@app.callback(no_args_is_help=True, invoke_without_command=True)

def main(
    username        : str   = typer.Option(..., "-u",  help="Username"),
    password        : str   = typer.Option(..., '-p',  help="Password or NTLM hash. (LM:NT)"),
    ip              : str   = typer.Option(..., '-ip',  help = "IP address or hostname of site server"),
    debug           : bool  = typer.Option(False, '-debug',help='Enable Verbose Logging'),
):



    logs_dir = init_logger(debug)
    cmpivot = CMPIVOT(username=username, password=password, ip=ip, debug=debug)
    cmpivot.run()