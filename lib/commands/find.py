import typer
from lib.attacks.find import SCCMHUNTER
from lib.logger import init_logger

app = typer.Typer()
COMMAND_NAME = 'find'
HELP = 'Enumerate LDAP for SCCM assets.'

@app.callback(no_args_is_help=True, invoke_without_command=True)

def main(
    username        : str   = typer.Option(None, "-u",  help="Username"),
    password        : str   = typer.Option(None, '-p',  help="Password"),
    domain          : str   = typer.Option(..., '-d',  help="Domain "),
    target_dom      : str   = typer.Option(None, '-t',  help='Target domain. Use if authenticating across trusts.'),
    dc_ip           : str   = typer.Option(..., '-dc-ip',  help = "IP address or FQDN of domain controller"),
    resolve         : bool   = typer.Option(False, "-resolve", help="Resolve nested group members. (Can be slow in large environments)"),   
    ldaps           : bool  = typer.Option(False, '-ldaps', help='Use LDAPS instead of LDAP'),
    kerberos        : bool  = typer.Option(False, "-k", help='Use Kerberos authentication'),
    no_pass         : bool  = typer.Option(False, "-no-pass", help="don't ask for password (useful for -k)"),
    hashes          : str   = typer.Option(None, "-hashes",metavar="LMHASH:NTHASH", help="LM and NT hashes, format is LMHASH:NTHASH"),
    aes             : str   = typer.Option(None, '-aes', metavar="HEX KEY", help='AES key to use for Kerberos Authentication (128 or 256 bits)'), 
    debug           : bool  = typer.Option(False, '-debug',help='Enable Verbose Logging'),
    all_computers   : bool  = typer.Option(False, '-all',help='Profile every computer in the domain to identify those hosting site system roles (WARNING: HEAVY)'),
):



    logs_dir = init_logger(debug)
    sccmhunter = SCCMHUNTER(username=username, password=password, domain=domain, target_dom=target_dom, dc_ip=dc_ip, resolve=resolve, ldaps=ldaps,
                            kerberos=kerberos, no_pass=no_pass, hashes=hashes, aes=aes, debug=debug, logs_dir=logs_dir, all_computers=all_computers)
    sccmhunter.run()
