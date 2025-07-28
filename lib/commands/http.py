import typer
from lib.attacks.http import HTTP
from lib.logger import init_logger

app = typer.Typer()
COMMAND_NAME = 'http'
HELP = 'Abuse client enrollment.'

@app.callback(no_args_is_help=True, invoke_without_command=True)

def main(
    username        : str   = typer.Option(None, "-u",  help="Username"),
    password        : str   = typer.Option(None, '-p',  help="Password"),
    domain          : str   = typer.Option(None, '-d',  help="Target domain"),
    dc_ip           : str   = typer.Option(None, '-dc-ip',  help = "IP address or FQDN of domain controller"),
    ldaps           : bool  = typer.Option(False, '-ldaps', help='Use LDAPS instead of LDAP'),
    channel_binding : bool   = typer.Option(None, '-binding', help='Use LDAP channel binding'),
    kerberos        : bool  = typer.Option(False, "-k", help='Use Kerberos authentication'),
    no_pass         : bool  = typer.Option(False, "-no-pass", help="don't ask for password (useful for -k)"),
    hashes          : str   = typer.Option(None, "-hashes",metavar="LMHASH:NTHASH", help="LM and NT hashes, format is LMHASH:NTHASH"),
    aes             : str   = typer.Option(None, '-aes', metavar="HEX KEY", help='AES key to use for Kerberos Authentication (128 or 256 bits)'), 
    debug           : bool  = typer.Option(False, '-debug',help='Enable Verbose Logging'),
    auto            : bool  = typer.Option(False, '-auto', help='Attempt to create a machine and recover policies with provided credentials.'),
    computer_pass   : str   = typer.Option(None, '-cp', help='Machine account password'),
    computer_hash   : str   = typer.Option(None, '-ch', help='Machine account NTLM hash. (can be used *only* for sccm push attack)'),
    computer_name   : str   = typer.Option(None, '-cn', help='Machine account name.'),
    uuid            : str   = typer.Option(None, '-uuid', help='UUID for manual request.'),
    mp              : str   = typer.Option(None, '-mp', help='Management Point to manually request from'),
    sleep           : str   = typer.Option(10, '-sleep', help='Time to wait between registering and requesting policies'),
    sccmpush        : bool  = typer.Option(False, "--sccm-push", "-sp", help="[Optional] Try to trigger sccm push on specified client"),
    sccmpush_client : str   = typer.Option(None, "--sccm-push-cn", "-spcn", help="[Mandatory with --sccm-push] client name to be registerd when performing sccm push attack which should be a controlled & reachable IP/FQDN)"),
    sccmpush_anon   : bool   = typer.Option(False, "--sccm-push-anonymous", "-spanon", help="try to perform sccm push without credentials"),
    platform_id     : str   = typer.Option("Microsoft Windows NT Workstation 2010.0","--sccm-push-plid", "-sppid", help="[Optional] Specify the plateformID when performing sccm push attack (ex: Microsoft Windows NT Server 10.0)")
    ):


    logs_dir = init_logger(debug)
    httphunter = HTTP(username=username, password=password, domain=domain, dc_ip=dc_ip,ldaps=ldaps,
                            kerberos=kerberos, no_pass=no_pass, hashes=hashes, aes=aes, debug=debug, auto=auto, channel_binding=channel_binding,
                            computer_pass=computer_pass, computer_name=computer_name, computer_hash=computer_hash, uuid=uuid, mp=mp, 
                            sp=sccmpush, spcn=sccmpush_client,sppid=platform_id, spanon=sccmpush_anon,sleep=sleep, logs_dir=logs_dir)
    httphunter.run()




