import typer
from lib.attacks.show import SHOW
from lib.logger import init_logger

app = typer.Typer()
COMMAND_NAME = 'show'
HELP = 'Show recon table results.'

@app.callback(no_args_is_help=True, invoke_without_command=True)

def main(
    users           : bool   = typer.Option(False, "-users", help="Show SCCM related users."),
    computers       : bool   = typer.Option(False, "-computers", help="Show SCCM related computers."),
    groups          : bool   = typer.Option(False, "-groups", help="Show SCCM related groups."),
    smb             : bool   = typer.Option(False, "-smb", help="Show SMB recon results."),
    all             : bool   = typer.Option(False, "-all", help="Show all recon results."),
    debug           : bool   = typer.Option(False, "-debug", help="Enable Verbose Logging")):


    logs_dir = init_logger(debug)
    show  = SHOW(users=users, computers=computers, groups=groups, smb=smb, all=all, logs_dir=logs_dir, debug=debug)
    show.run()
