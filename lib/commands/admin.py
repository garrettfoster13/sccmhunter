import typer
from lib.attacks.admin import CONSOLE
from lib.logger import init_logger

app = typer.Typer()
COMMAND_NAME = 'admin'
HELP = 'Run administrative commands through the AdminService API.'

@app.callback(no_args_is_help=True, invoke_without_command=True)

def main(
    username        : str   = typer.Option(None, "-u",  help="Username"),
    password        : str   = typer.Option(None, '-p',  help="Password or NTLM hash. (LM:NT)"),
    ip              : str   = typer.Option(..., '-ip',  help = "IP address or hostname of site server"),
    kerberos        : bool  = typer.Option(False, '-k', help="Use kerberos authentication"),
    domain          : str   = typer.Option(None, '-d', help="Target domain name"),
    kdc             : str   = typer.Option(None, '-dc', help="Target domain controller for Kerberos auth"),
    debug           : bool  = typer.Option(False, '-debug',help='Enable Verbose Logging'),
    auser           : str   = typer.Option(None, '-au', help="Optional script approval username"),
    apassword       : str   = typer.Option(None, '-ap', help="Optional script approval password")
):



    logs_dir = init_logger(debug)
    cmpivot = CONSOLE(username=username, password=password, kerberos=kerberos, domain=domain, kdc=kdc, ip=ip, debug=debug, logs_dir=logs_dir, auser=auser, apassword=apassword)
    cmpivot.run()
