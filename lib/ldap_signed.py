"""Adapter exposing ldap3-style Connection/Entry API over impacket.ldap.

Used when --signing is set, because ldap3 does not implement NTLMSSP message
signing. impacket's LDAPConnection does, and supports Kerberos binds too.

Only the surface actually consumed by lib/attacks/*.py is implemented:
  session.extend.standard.paged_search(search_base, search_filter, attributes, ...)
  session.entries                 -> list[SignedEntry]
  entry[attr_name]                -> SignedAttribute (case-insensitive lookup)
  entry[attr_name].value          -> Python value (str/int/bytes/list)
  str(entry[attr_name])           -> ldap3-style string repr
  'name' in entry                 -> bool (case-insensitive)
  entry.entry_to_json()           -> JSON str {"dn": ..., "attributes": {...}}
"""
import base64
import json
from binascii import unhexlify

from impacket.ldap import ldap as impacket_ldap
from impacket.ldap.ldap import LDAPSearchError
from impacket.ldap.ldapasn1 import SearchResultEntry

from lib.logger import logger


# Attributes whose values AD returns as textual digits but callers compare as int.
_INT_ATTRS = {
    'samaccounttype',
    'useraccountcontrol',
    'admincount',
    'primarygroupid',
    'instancetype',
    'grouptype',
}

# Attributes that are always raw binary on the wire and must NOT be utf-8
# decoded. Their bytes can coincidentally be valid UTF-8 (e.g. an all-low-byte
# SID prefix), so we can't detect them via decode failure.
_BINARY_ATTRS = {
    'objectsid',
    'objectguid',
    'ntsecuritydescriptor',
    'msds-managedpasswordblob',
    'msds-generationid',
    'unicodepwd',
    'userpassword',
    'usercertificate',
    'cacertificate',
    'thumbnailphoto',
    'jpegphoto',
    'sidhistory',
    'logonhours',
}


def _decode_value(attr_name_lower, raw):
    """Decode an impacket attribute value (bytes) to a Python value.

    ldap3 formatter parity is best-effort: known binary attrs stay as bytes,
    text attrs decode to str, integer-like attrs become int, undecodable
    bytes stay as bytes.
    """
    if isinstance(raw, (bytes, bytearray)):
        b = bytes(raw)
    else:
        b = bytes(str(raw), 'utf-8', errors='strict')

    if attr_name_lower in _BINARY_ATTRS:
        return b

    try:
        text = b.decode('utf-8')
    except UnicodeDecodeError:
        return b

    if attr_name_lower in _INT_ATTRS:
        try:
            return int(text)
        except ValueError:
            return text
    return text


class SignedAttribute:
    """Stand-in for ldap3's Attribute. Holds decoded values for one attribute."""

    def __init__(self, name, values):
        self.name = name
        self.values = values  # list of decoded values

    @property
    def value(self):
        if not self.values:
            return None
        if len(self.values) == 1:
            return self.values[0]
        return list(self.values)

    @property
    def raw_values(self):
        return list(self.values)

    def __str__(self):
        v = self.value
        if v is None:
            return ''
        if isinstance(v, bytes):
            return str(v)
        return str(v)

    def __repr__(self):
        return f'SignedAttribute({self.name!r}, {self.values!r})'

    def __eq__(self, other):
        return self.value == other

    def __iter__(self):
        return iter(self.values)


class SignedEntry:
    """Stand-in for ldap3's Entry. Case-insensitive attribute access."""

    def __init__(self, dn, attributes):
        self._dn = dn
        # attributes: dict[str_original_name] -> list[decoded values]
        self._attrs = attributes
        self._lower_index = {k.lower(): k for k in attributes.keys()}

    @property
    def entry_dn(self):
        return self._dn

    def __contains__(self, name):
        return name.lower() in self._lower_index

    def __getitem__(self, name):
        key_lower = name.lower()
        if key_lower not in self._lower_index:
            raise KeyError(name)
        real = self._lower_index[key_lower]
        return SignedAttribute(real, self._attrs[real])

    def entry_to_json(self, **_ignored):
        """Match ldap3 output shape: {"dn": "...", "attributes": {name: value_or_list}}.

        Bytes that aren't utf-8 decodable are emitted as {"encoding": "base64",
        "encoded": "<b64>"} to mirror ldap3.utils.conv.json_encode_b64.
        """
        payload = {'dn': self._dn, 'attributes': {}}
        for name, values in self._attrs.items():
            rendered = [_jsonable(v) for v in values]
            payload['attributes'][name] = rendered[0] if len(rendered) == 1 else rendered
        return json.dumps(payload, ensure_ascii=True, sort_keys=True, indent=4, separators=(',', ': '))


def _jsonable(v):
    # Bytes reach here only for attrs that _decode_value classified as binary,
    # so emit them as base64 to match ldap3.utils.conv.json_encode_b64 shape.
    if isinstance(v, bytes):
        return {'encoding': 'base64', 'encoded': base64.b64encode(v).decode('ascii')}
    return v


class _StandardExtend:
    def __init__(self, session):
        self._session = session

    def paged_search(self, search_base=None, search_filter='(objectClass=*)',
                     attributes=None, controls=None, paged_size=500,
                     generator=False, **_ignored):
        # impacket expects a list for attributes; accept string or list from callers.
        if attributes is None:
            attrs = []
        elif isinstance(attributes, str):
            attrs = [attributes] if attributes != '*' else []
        else:
            attrs = list(attributes)

        try:
            answers = self._session._conn.search(
                searchBase=search_base,
                searchFilter=search_filter,
                attributes=attrs,
            )
        except LDAPSearchError as e:
            logger.debug(f'[LDAP-signed] search failed | {e}')
            self._session.entries = []
            raise

        entries = []
        for msg in answers:
            if not isinstance(msg, SearchResultEntry):
                continue
            dn = str(msg['objectName'])
            attrs_map = {}
            for part in msg['attributes']:
                attr_name = str(part['type'])
                attr_name_lower = attr_name.lower()
                decoded = [_decode_value(attr_name_lower, v.asOctets()) for v in part['vals']]
                attrs_map[attr_name] = decoded
            entries.append(SignedEntry(dn, attrs_map))

        self._session.entries = entries
        return entries


class _Extend:
    def __init__(self, session):
        self.standard = _StandardExtend(session)


class SignedLDAPSession:
    """ldap3-compatible wrapper over impacket.ldap.LDAPConnection with signing."""

    def __init__(self, impacket_conn):
        self._conn = impacket_conn
        self.entries = []
        self.extend = _Extend(self)

    def unbind(self):
        try:
            self._conn.close()
        except Exception:
            pass


def _normalize_hashes(lmhash, nthash):
    if lmhash == '' and nthash == '':
        return '', ''
    if lmhash == '':
        lmhash = 'aad3b435b51404eeaad3b435b51404ee'
    return lmhash, nthash


def build_signed_session(target, domain, username, password, lmhash, nthash,
                         domain_controller, kerberos, hashes, aes_key):
    """Build and bind an impacket LDAPConnection (with signing), return a SignedLDAPSession.

    target              - LDAP server hostname/IP used for the connection URL
    domain_controller   - IP used as dstIp (optional); impacket resolves target otherwise
    kerberos            - bool; use GSSAPI bind
    hashes              - truthy when --hashes was passed (LM:NT)
    aes_key             - Kerberos AES key (optional)
    """
    base_dn = _domain_to_base_dn(domain)
    url = f'ldap://{target}'
    logger.debug(f'[LDAP-signed] connecting | url={url} base={base_dn} dstIp={domain_controller}')
    conn = impacket_ldap.LDAPConnection(url, baseDN=base_dn, dstIp=domain_controller)

    if kerberos:
        logger.debug(f'[LDAP-signed] kerberosLogin | user={username} domain={domain}')
        conn.kerberosLogin(
            username or '',
            password or '',
            domain or '',
            lmhash or '',
            nthash or '',
            aes_key or '',
            kdcHost=domain_controller,
        )
    else:
        if hashes:
            lmhash, nthash = _normalize_hashes(lmhash or '', nthash or '')
            logger.debug(f'[LDAP-signed] NTLM login (hash) | user={username} domain={domain}')
        else:
            logger.debug(f'[LDAP-signed] NTLM login (password) | user={username} domain={domain}')
        conn.login(
            username or '',
            password or '',
            domain or '',
            lmhash or '',
            nthash or '',
        )

    return SignedLDAPSession(conn)


def _domain_to_base_dn(domain):
    return ','.join(f'DC={p}' for p in domain.split('.')) if domain else ''
