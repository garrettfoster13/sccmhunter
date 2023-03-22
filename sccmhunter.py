
from impacket.smbconnection import SMBConnection
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, ACCESS_ALLOWED_ACE
from binascii import unhexlify
from ldap3 import ANONYMOUS
import argparse
from getpass import getpass
import ldap3
import json
import ssl
import sys
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5 import constants
from impacket.krb5.types import Principal
import os
import requests


def arg_parse():
    parser = argparse.ArgumentParser(add_help=True, description=
    '''Tool to enumerate a target environment for SCCM HTTP endpoints.
    ''')

    parser.add_argument('-u',action='store', help='Username')
    parser.add_argument('-p', action='store', help='Password')
    parser.add_argument('-d', action='store', help='Domain Name')
    parser.add_argument('-dc-ip', action='store', help='IP address or FQDN of domain controller')
    parser.add_argument('-t', help='Target trusted domain to search.', required=False,)
    parser.add_argument('-ldaps', action='store_true', help='Use LDAPS instead of LDAP')
    parser.add_argument('-k', '--kerberos', action='store_true', help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')
    parser.add_argument('-no-pass', action='store_true', help='Don\'t ask for password. (Useful for -k')
    parser.add_argument("-hashes", metavar="LMHASH:NTHASH", help="LM and NT hashes, format is LMHASH:NTHASH",)
    parser.add_argument('-aes', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')


    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    return args

def get_dn(domain):
    components = domain.split('.')
    base = ''
    for comp in components:
        base += f',DC={comp}'
    
    return base[1:]

def get_machine_name(domain_controller, domain):
    if domain_controller is not None:
        s = SMBConnection(domain_controller, domain_controller)
    else:
        s = SMBConnection(domain, domain)
    try:
        s.login('', '')
    except Exception:
        if s.getServerName() == '':
            raise Exception('Error while anonymous logging into %s' % domain)
    else:
        s.logoff()
    return s.getServerName()

def init_ldap_connection(target, tls_version, domain, username, password, lmhash, nthash, domain_controller, kerberos, hashes, aesKey):
    user = '%s\\%s' % (domain, username)
    if tls_version is not None:
        use_ssl = True
        port = 636
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=tls_version)
    else:
        use_ssl = False
        port = 389
        tls = None
    ldap_server = ldap3.Server(target, get_info=ldap3.ALL, port=port, use_ssl=use_ssl, tls=tls)
    if kerberos:
        ldap_session = ldap3.Connection(ldap_server)
        ldap_session.bind()
        ldap3_kerberos_login(ldap_session, target, username, password, domain, lmhash, nthash, aesKey, kdcHost=domain_controller)
    elif hashes is not None:
        if lmhash == "":
            lmhash = "aad3b435b51404eeaad3b435b51404ee"
        ldap_session = ldap3.Connection(ldap_server, user=user, password=lmhash + ":" + nthash, authentication=ldap3.NTLM, auto_bind=True)
    elif username == '' and password == '':
        ldap_session = ldap3.Connection(ldap_server, authentication=ANONYMOUS, auto_bind=True)
    else:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=password, authentication=ldap3.NTLM, auto_bind=True)

    return ldap_server, ldap_session

def init_ldap_session(domain, username, password, lmhash, nthash, kerberos, domain_controller, ldaps, hashes, aesKey):
    if kerberos:
        #target = domain_controller
        netbiosname = get_machine_name(domain_controller, domain)
        #dontlookhereok
        target = netbiosname + "." + domain
    else:
        if domain_controller is not None:
            target = domain_controller
        else:
            target = domain

    if ldaps:
        try:
            return init_ldap_connection(target, ssl.PROTOCOL_TLSv1_2, domain, username, password, lmhash, nthash, domain_controller, kerberos, hashes, aesKey)
        except ldap3.core.exceptions.LDAPSocketOpenError:
            return init_ldap_connection(target, ssl.PROTOCOL_TLSv1, domain, username, password, lmhash, nthash, domain_controller, kerberos, hashes, aesKey)
    else:
        return init_ldap_connection(target, None, domain, username, password, lmhash, nthash, domain_controller, kerberos, hashes, aesKey)

def ldap3_kerberos_login(connection, target, user, password, domain='', lmhash='', nthash='', aesKey='', kdcHost=None, TGT=None, TGS=None, useCache=True):
    from pyasn1.codec.ber import encoder, decoder
    from pyasn1.type.univ import noValue
    """
    logins into the target system explicitly using Kerberos. Hashes are used if RC4_HMAC is supported.
    :param string user: username
    :param string password: password for the user
    :param string domain: domain where the account is valid for (required)
    :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
    :param string nthash: NTHASH used to authenticate using hashes (password is not used)
    :param string aesKey: aes256-cts-hmac-sha1-96 or aes128-cts-hmac-sha1-96 used for Kerberos authentication
    :param string kdcHost: hostname or IP Address for the KDC. If None, the domain will be used (it needs to resolve tho)
    :param struct TGT: If there's a TGT available, send the structure here and it will be used
    :param struct TGS: same for TGS. See smb3.py for the format
    :param bool useCache: whether or not we should use the ccache for credentials lookup. If TGT or TGS are specified this is False
    :return: True, raises an Exception if error.
    """

    if lmhash != '' or nthash != '':
        if len(lmhash) % 2:
            lmhash = '0' + lmhash
        if len(nthash) % 2:
            nthash = '0' + nthash
        try:  # just in case they were converted already
            lmhash = unhexlify(lmhash)
            nthash = unhexlify(nthash)
        except TypeError:
            pass

    # Importing down here so pyasn1 is not required if kerberos is not used.
    from impacket.krb5.ccache import CCache
    from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal, KerberosTime, Ticket
    import datetime

    if TGT is not None or TGS is not None:
        useCache = False

    if useCache:
        try:
            ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
        except Exception as e:
            # No cache present
            print(e)
            pass
        else:
            # retrieve domain information from CCache file if needed
            if domain == '':
                domain = ccache.principal.realm['data'].decode('utf-8')
                print ('Domain retrieved from CCache: %s' % domain)

            print('Using Kerberos Cache: %s' % os.getenv('KRB5CCNAME'))
            principal = 'ldap/%s@%s' % (target.upper(), domain.upper())

            creds = ccache.getCredential(principal)
            if creds is None:
                # Let's try for the TGT and go from there
                principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
                creds = ccache.getCredential(principal)
                if creds is not None:
                    TGT = creds.toTGT()
                    print('Using TGT from cache')
                else:
                    print('No valid credentials found in cache')
            else:
                TGS = creds.toTGS(principal)
                print('Using TGS from cache')

            # retrieve user information from CCache file if needed
            if user == '' and creds is not None:
                user = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
                print('Username retrieved from CCache: %s' % user)
            elif user == '' and len(ccache.principal.components) > 0:
                user = ccache.principal.components[0]['data'].decode('utf-8')
                print('Username retrieved from CCache: %s' % user)

    # First of all, we need to get a TGT for the user
    userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    if TGT is None:
        if TGS is None:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash, aesKey, kdcHost)
    else:
        tgt = TGT['KDC_REP']
        cipher = TGT['cipher']
        sessionKey = TGT['sessionKey']

    if TGS is None:
        serverName = Principal('ldap/%s' % target, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher, sessionKey)
    else:
        tgs = TGS['KDC_REP']
        cipher = TGS['cipher']
        sessionKey = TGS['sessionKey']

        # Let's build a NegTokenInit with a Kerberos REQ_AP

    blob = SPNEGO_NegTokenInit()

    # Kerberos
    blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

    # Let's extract the ticket from the TGS
    tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs['ticket'])

    # Now let's build the AP_REQ
    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = []
    apReq['ap-options'] = constants.encodeFlags(opts)
    seq_set(apReq, 'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = domain
    seq_set(authenticator, 'cname', userName.components_to_asn1)
    now = datetime.datetime.utcnow()

    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encodedAuthenticator = encoder.encode(authenticator)

    # Key Usage 11
    # AP-REQ Authenticator (includes application authenticator
    # subkey), encrypted with the application session key
    # (Section 5.5.1)
    encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

    apReq['authenticator'] = noValue
    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

    blob['MechToken'] = encoder.encode(apReq)

    request = ldap3.operation.bind.bind_operation(connection.version, ldap3.SASL, user, None, 'GSS-SPNEGO',
                                                  blob.getData())

    # Done with the Kerberos saga, now let's get into LDAP
    if connection.closed:  # try to open connection if closed
        connection.open(read_server_info=False)

    connection.sasl_in_progress = True
    response = connection.post_send_single_response(connection.send('bindRequest', request, None))
    connection.sasl_in_progress = False
    if response[0]['result'] != 0:
        raise Exception(response)

    connection.bound = True

    return True


class sccmhunter:
    
    def __init__(self, ldap_server, ldap_session, search_base):
        self.ldap_server = ldap_server
        self.ldap_session = ldap_session
        self.attributes = "dNSHostName"
        self.search_filter = "(objectclass=mssmsmanagementpoint)"
        self.search_base=search_base

    def fetch_sccm(self):
        servers = []
        print(f'[*] Searching for SCCM servers...')
        try:
            self.ldap_session.extend.standard.paged_search(self.search_base, self.search_filter, attributes=self.attributes,paged_size=500, generator=False)  
        except ldap3.core.exceptions.LDAPAttributeError as e:
            print()
            print (f'Error: {str(e)}')
            exit()
        if self.ldap_session.entries:
            print(f"[+] Found {len(self.ldap_session.entries)} site servers.")
            for entry in self.ldap_session.entries:
                # json_entry = json.loads(entry.entry_to_json())
                # attributes = json_entry['attributes'].keys()
                hostname =  entry['dNSHostname']
                print(f"[+] {hostname}")
                servers.append(hostname)
            self.http_hunter(servers)
            return True
        else:
            print("[-] No SCCM Servers found.")
            return False
        
    def http_hunter(self, servers):
        validated = []                   
        for server in servers:
            url=(f"http://{server}/ccm_system_windowsauth")
            url2=(f"http://{server}/ccm_system/")
            try:
                x = requests.get(url, timeout=5)
                x2 = requests.get(url2,timeout=5)
                if x.status_code == 401:
                    print("[+] SCCM HTTP Endpoint Found!")
                    print(f"[+] {url}")
                    validated.append(url)
                if x2.status_code == 401:
                    print("[+] SCCM HTTP Endpoint Found!")
                    print(f"[+] {url2}")
                    validated.append(url2)
            except requests.exceptions.Timeout:
                print(f"[-] {server} connection timed out.")
            except requests.ConnectionError as e:
                print (f"[-] {server} doesn't appear to be a SCCM server.")
                pass
        if validated:
            self.printlog(validated)
        else:
            print("[-] No HTTP endpoints found :(")
 

    def printlog(self, validated):
        filename = (f'sccmhunter.log')
        print(f'[+] Results saved to {os.getcwd()}/{filename}')
        for valid in validated:
            with open(filename, 'a') as f:
                f.write("{}\n".format(valid))
                f.close

def main():
    args = arg_parse()
    args.lmhash = ""
    args.nthash = ""
    if args.hashes:
        args.lmhash, args.nthash = args.hashes.split(':')
    if not (args.p or args.lmhash or args.nthash or args.aes or args.no_pass):
            args.p = getpass("Password:")    
    try:
        ldap_server, ldap_session = init_ldap_session(domain=args.d, username=args.u, password=args.p, lmhash=args.lmhash, nthash=args.nthash, kerberos=args.kerberos, domain_controller=args.dc_ip, aesKey=args.aes, hashes=args.hashes, ldaps=args.ldaps)
        print('[+] Bind successful {}'.format(ldap_server))
    except ldap3.core.exceptions.LDAPSocketOpenError as e: 
        if 'invalid server address' in str(e):
            print (f'Invalid server address - {args.d}')
        else:
            print ('Error connecting to LDAP server')
            print()
            print(e)
        exit()
    except ldap3.core.exceptions.LDAPBindError as e:
        print(f'Error: {str(e)}')
        exit()
    if args.t:
        search_base = get_dn(args.t)
    else:
        search_base = get_dn(args.d)
    finder=sccmhunter(ldap_server, ldap_session, search_base)
    results = finder.fetch_sccm()





if __name__ == '__main__':
    main()

