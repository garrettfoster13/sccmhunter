import typer
from lib.attacks.mssql import MSSQL
from lib.logger import init_logger

app = typer.Typer()
COMMAND_NAME = 'mssql'
HELP = 'MSSQL relay abuse.'

@app.callback(no_args_is_help=True, invoke_without_command=True)

def main(
    username        : str   = typer.Option(None, "-u",  help="Username"),
    password        : str   = typer.Option(None, '-p',  help="Password"),
    domain          : str   = typer.Option(..., '-d',  help="Target domain"),
    dc_ip           : str   = typer.Option(..., '-dc-ip',  help = "IP address or FQDN of domain controller"),
    ldaps           : bool  = typer.Option(False, '-ldaps', help='Use LDAPS instead of LDAP'),
    kerberos        : bool  = typer.Option(False, "-k", help='Use Kerberos authentication'),
    no_pass         : bool  = typer.Option(False, "-no-pass", help="don't ask for password (useful for -k)"),
    hashes          : str   = typer.Option(None, "-hashes",metavar="LMHASH:NTHASH", help="LM and NT hashes, format is LMHASH:NTHASH"),
    aes             : str   = typer.Option(None, '-aes', metavar="HEX KEY", help='AES key to use for Kerberos Authentication (128 or 256 bits)'), 
    debug           : bool  = typer.Option(False, '-debug',help='Enable Verbose Logging'),
    target_user     : str   = typer.Option(..., '-tu', help="Controlled user to grant permissions to."),
    stacked         : bool  = typer.Option(False, '-stacked', help="Provide a single stacked query for relaying."),
    site_code       : str   = typer.Option(..., '-sc', help="Target site code to add user to.")):


    mssqlhunter = MSSQL(username=username, password=password, domain=domain, dc_ip=dc_ip,ldaps=ldaps,
                            kerberos=kerberos, no_pass=no_pass, hashes=hashes, aes=aes, debug=debug, 
                            target_user=target_user, stacked=stacked, site_code=site_code)
    init_logger(debug)
    mssqlhunter.run()


