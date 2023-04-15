import typer
from lib.attacks.find import SCCMHUNTER
from lib.logger import init_logger

app = typer.Typer()
COMMAND_NAME = 'find'
HELP = 'Enumerate LDAP for SCCM Servers'

@app.callback(no_args_is_help=True, invoke_without_command=True)

def main(
    username        : str   = typer.Option(None, "-u",  help="Username"),
    password        : str   = typer.Option(None, '-p',  help="Password"),
    domain          : str   = typer.Option(..., '-d',  help="Target domain"),
    target_dom      : str   = typer.Option(None, '-t',  help='Use if authenticating across trusts.'),
    dc_ip           : str   = typer.Option(..., '-dc-ip',  help = "IP address or FQDN of domain controller"),
    ldaps           : bool  = typer.Option(False, '-ldaps', help='Use LDAPS instead of LDAP'),
    kerberos        : bool  = typer.Option(False, "-k", help='Use Kerberos authentication'),
    no_pass         : bool  = typer.Option(False, "-no-pass", help="don't ask for password (useful for -k)"),
    hashes          : str   = typer.Option(None, "-hashes",metavar="LMHASH:NTHASH", help="LM and NT hashes, format is LMHASH:NTHASH"),
    aes             : str   = typer.Option(None, '-aes', metavar="HEX KEY", help='AES key to use for Kerberos Authentication (128 or 256 bits)'), 
    debug           : bool  = typer.Option(False, '-debug',help='Enable Verbose Logging'),
    hide_banner      : bool  = typer.Option(False, '-hide', help='Hide banner.')):



    logs_dir = init_logger(debug)
    sccmhunter = SCCMHUNTER(username=username, password=password, domain=domain, target_dom=target_dom, dc_ip=dc_ip,ldaps=ldaps,
                            kerberos=kerberos, no_pass=no_pass, hashes=hashes, aes=aes, debug=debug, logs_dir=logs_dir, hide_banner=hide_banner)
    sccmhunter.run()
