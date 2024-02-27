import typer
from lib.attacks.show import SHOW
from lib.logger import init_logger

app = typer.Typer()
COMMAND_NAME = 'show'
HELP = 'Show and/or recon table results.'

@app.callback(no_args_is_help=True, invoke_without_command=True)

def main(       
    siteservers     : bool   = typer.Option(False, "-siteservers", help="Show SiteServers table"),
    mps             : bool   = typer.Option(False, "-mps", help="Show ManagementPoints table"),
    users           : bool   = typer.Option(False, "-users", help="Show SCCM related users."),
    computers       : bool   = typer.Option(False, "-computers", help="Show SCCM related computers."),
    groups          : bool   = typer.Option(False, "-groups", help="Show SCCM related groups."),
    creds           : bool   = typer.Option(False, "-creds", help="Show recovered SCCM credentials."),
    all             : bool   = typer.Option(False, "-all", help="Show all recon results."),
    json            : bool   = typer.Option(False, "-json", help="Export chosen results in JSON."),
    csv             : bool   = typer.Option(False, "-csv", help="Export chosen results in CSV."),
    debug           : bool   = typer.Option(False, "-debug", help="Enable Verbose Logging")):


    logs_dir = init_logger(debug)
    show  = SHOW(users=users, computers=computers, groups=groups, creds=creds, all=all, logs_dir=logs_dir, site_servers=siteservers, mps=mps, csv=csv, js=json, debug=debug)
    show.run()
