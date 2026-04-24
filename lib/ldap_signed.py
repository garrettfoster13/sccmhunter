import base64
import json

from impacket.ldap import ldap as impacket_ldap
from impacket.ldap.ldap import LDAPSearchError
from impacket.ldap.ldapasn1 import SearchResultEntry, SDFlagsControl

from lib.logger import logger


_SD_FLAGS_OID = '1.2.840.113556.1.4.801'

# AD returns these as raw bytes; UTF-8 decoding would silently corrupt them.
_BINARY_ATTRS = {'objectsid', 'objectguid', 'ntsecuritydescriptor'}

# AD returns these as digit strings; callers compare them as ints.
_INT_ATTRS = {'samaccounttype'}


def _decode_value(attr_name_lower, raw):
    b = bytes(raw) if isinstance(raw, (bytes, bytearray)) else bytes(str(raw), 'utf-8')

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
    def __init__(self, name, values):
        self.name = name
        self.values = values

    @property
    def value(self):
        if not self.values:
            return None
        if len(self.values) == 1:
            return self.values[0]
        return list(self.values)

    def __str__(self):
        v = self.value
        if v is None:
            return ''
        return str(v)

    def __eq__(self, other):
        return self.value == other


class SignedEntry:
    def __init__(self, dn, attributes):
        self._dn = dn
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
        payload = {'dn': self._dn, 'attributes': {}}
        for name, values in self._attrs.items():
            rendered = [_jsonable(v) for v in values]
            payload['attributes'][name] = rendered[0] if len(rendered) == 1 else rendered
        return json.dumps(payload, ensure_ascii=True, sort_keys=True, indent=4, separators=(',', ': '))


def _jsonable(v):
    if isinstance(v, bytes):
        return {'encoding': 'base64', 'encoded': base64.b64encode(v).decode('ascii')}
    return v


def _translate_controls(controls):
    if not controls:
        return None
    out = []
    for ctrl in controls:
        try:
            if str(ctrl['controlType']) == _SD_FLAGS_OID:
                out.append(SDFlagsControl(criticality=True, flags=0x07))
                continue
        except Exception:
            pass
        out.append(ctrl)
    return out


class _StandardExtend:
    def __init__(self, session):
        self._session = session

    def paged_search(self, search_base=None, search_filter='(objectClass=*)',
                     attributes=None, controls=None, paged_size=500,
                     generator=False, **_ignored):
        if attributes is None:
            attrs = []
        elif isinstance(attributes, str):
            attrs = [attributes] if attributes != '*' else []
        else:
            attrs = list(attributes)

        search_controls = _translate_controls(controls)

        try:
            answers = self._session._conn.search(
                searchBase=search_base,
                searchFilter=search_filter,
                attributes=attrs,
                searchControls=search_controls,
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
                decoded = [_decode_value(attr_name.lower(), v.asOctets()) for v in part['vals']]
                attrs_map[attr_name] = decoded
            entries.append(SignedEntry(dn, attrs_map))

        self._session.entries = entries
        return entries


class _Extend:
    def __init__(self, session):
        self.standard = _StandardExtend(session)


class SignedLDAPSession:
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
    base_dn = _domain_to_base_dn(domain)
    url = f'ldap://{target}'
    logger.debug(f'[LDAP-signed] connecting | url={url} base={base_dn} dstIp={domain_controller}')
    conn = impacket_ldap.LDAPConnection(url, baseDN=base_dn, dstIp=domain_controller)

    if kerberos:
        logger.debug(f'[LDAP-signed] kerberosLogin | user={username} domain={domain}')
        conn.kerberosLogin(
            username or '', password or '', domain or '',
            lmhash or '', nthash or '', aes_key or '',
            kdcHost=domain_controller,
        )
    else:
        if hashes:
            lmhash, nthash = _normalize_hashes(lmhash or '', nthash or '')
            logger.debug(f'[LDAP-signed] NTLM login (hash) | user={username} domain={domain}')
        else:
            logger.debug(f'[LDAP-signed] NTLM login (password) | user={username} domain={domain}')
        conn.login(
            username or '', password or '', domain or '',
            lmhash or '', nthash or '',
        )

    return SignedLDAPSession(conn)


def _domain_to_base_dn(domain):
    return ','.join(f'DC={p}' for p in domain.split('.')) if domain else ''
