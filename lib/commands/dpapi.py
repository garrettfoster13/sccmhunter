import typer
from lib.attacks.dpapi import DPAPI
from lib.logger import init_logger

app = typer.Typer()
COMMAND_NAME = 'dpapi'
HELP = 'Extract NAA credentials from DPAPI encrypted blobs.'

@app.callback(no_args_is_help=True, invoke_without_command=True)

def main(
    username        : str   = typer.Option(..., "-u",  help="Username"),
    password        : str   = typer.Option('', '-p',  help="Password"),
    domain          : str   = typer.Option('', '-d',  help="Target domain"),
    dc_ip           : str   = typer.Option(None, '-dc-ip',  help = "IP address or FQDN of domain controller"),
    target          : str   = typer.Option(..., '-target',  help = "Target hostname"),
    kerberos        : bool  = typer.Option(False, "-k", help='Use Kerberos authentication'),
    no_pass         : bool  = typer.Option(False, "-no-pass", help="don't ask for password (useful for -k)"),
    hashes          : str   = typer.Option(None, "-hashes",metavar="LMHASH:NTHASH", help="LM and NT hashes, format is LMHASH:NTHASH"),
    aes             : str   = typer.Option(None, '-aes', metavar="HEX KEY", help='AES key to use for Kerberos Authentication (128 or 256 bits)'), 
    debug           : bool  = typer.Option(False, '-debug',help='Enable Verbose Logging')):

    logs_dir = init_logger(debug)
    dpapihunter = DPAPI(remoteName=target, username=username, password=password, domain=domain, 
                        kerberos=kerberos, no_pass=no_pass, hashes=hashes, aes=aes, kdc=dc_ip, logs_dir=logs_dir)
    dpapihunter.run()