#!/usr/bin/env python3

import argparse
import re
import secrets
import base64

from hashlib import sha3_256
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pyasn1.type import univ, char
from pyasn1.codec.der.encoder import encode

from pyasn1_alt_modules import rfc2985, rfc2986, rfc8410, rfc5280

OID_CABF_CA_SIGNING_NONCE = univ.ObjectIdentifier('2.23.140.41')
OID_CABF_CA_APPLICANT_NONCE = univ.ObjectIdentifier('2.23.140.42')

APPLICANT_SIGNING_NONCE_OCTET_COUNT = 16
RANDOM_VALUE_REGEX = re.compile(r'^[a-f0-9]+$', re.IGNORECASE)


def _validate_random_value(value):
    if RANDOM_VALUE_REGEX.match(value):
        return value
    else:
        raise ValueError(f'Invalid Random Value syntax')


def _read_private_key(f):
    try:
        key_octets = f.read()

        return ed25519.Ed25519PrivateKey.from_private_bytes(key_octets)
    finally:
        f.close()


def _generate_applicant_signing_nonce():
    return secrets.token_hex(APPLICANT_SIGNING_NONCE_OCTET_COUNT)


def _create_octet_string_attribute(oid, value_str):
    attr = rfc2986.Attribute()

    attr['type'] = oid
    attr['values'].append(univ.OctetString(value_str.encode('us-ascii')))

    return attr


def _create_onion_domain_name(public_key):
    public_key_octets = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    h = sha3_256()
    h.update(b'.onion checksum' + public_key_octets + b'\x03')
    checksum = h.digest()[:2]

    second_level_domain_name = base64.b32encode(public_key_octets + checksum + b'\x03').decode('us-ascii').lower()

    return f'{second_level_domain_name}.onion'


def _create_san_extension_request(public_key):
    domain_name = _create_onion_domain_name(public_key)

    attr = rfc2986.Attribute()
    attr['type'] = rfc2985.pkcs_9_at_extensionRequest

    san_ext = rfc5280.SubjectAltName()

    dns_name = rfc5280.GeneralName()
    dns_name.setComponentByName('dNSName', domain_name)

    san_ext.append(dns_name)

    extensions = rfc5280.Extensions()

    extension = rfc5280.Extension()
    extension['extnID'] = rfc5280.id_ce_subjectAltName
    extension['extnValue'] = encode(san_ext)

    extensions.append(extension)

    attr['values'].append(extensions)

    return attr


def _create_certification_request_info(public_key: ed25519.Ed25519PublicKey, ca_signing_nonce_str,
                                       applicant_signing_nonce_str):
    cri = rfc2986.CertificationRequestInfo()
    cri['version'] = univ.Integer(0)

    rdn_sequence = rfc2986.RDNSequence()
    rdn = rfc2986.RelativeDistinguishedName()

    atv = rfc2986.AttributeTypeAndValue()
    atv['type'] = rfc5280.id_at_commonName
    cn = rfc5280.X520CommonName()
    cn.setComponentByName('utf8String', _create_onion_domain_name(public_key))

    atv['value'] = cn

    rdn.append(atv)
    rdn_sequence.append(rdn)

    cri['subject'].setComponentByName('rdnSequence', rdn_sequence)

    spki = rfc2986.SubjectPublicKeyInfo()
    algo_id = rfc2986.AlgorithmIdentifier()
    algo_id['algorithm'] = rfc8410.id_Ed25519

    spki['algorithm'] = algo_id

    key_hex = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    spki['subjectPublicKey'] = univ.BitString.fromHexString(key_hex)
    cri['subjectPKInfo'] = spki

    cri['attributes'].append(_create_octet_string_attribute(OID_CABF_CA_SIGNING_NONCE, ca_signing_nonce_str))
    cri['attributes'].append(_create_octet_string_attribute(OID_CABF_CA_APPLICANT_NONCE, applicant_signing_nonce_str))
    cri['attributes'].append(_create_san_extension_request(public_key))

    return cri


def _sign_certification_request(private_key, certification_request_info):
    cri_der = encode(certification_request_info)

    signature_hex = private_key.sign(cri_der).hex()

    csr = rfc2986.CertificationRequest()
    csr['certificationRequestInfo'] = certification_request_info
    csr['signatureAlgorithm'] = certification_request_info['subjectPKInfo']['algorithm']
    csr['signature'] = univ.BitString.fromHexString(signature_hex)

    return csr


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='onion-maker')
    parser.add_argument('random_value', help='The Random Value supplied by the CA', type=_validate_random_value)
    parser.add_argument('private_key_file', type=argparse.FileType('rb'), help='The private key of the Tor v3 service')

    args = parser.parse_args()

    private_key = _read_private_key(args.private_key_file)

    certification_request_info = _create_certification_request_info(private_key.public_key(), args.random_value,
                                                                    _generate_applicant_signing_nonce())

    csr_asn1 = _sign_certification_request(private_key, certification_request_info)

    csr_der = encode(csr_asn1)

    csr_pem = x509.load_der_x509_csr(csr_der)

    print(csr_pem.public_bytes(serialization.Encoding.PEM).decode('us-ascii'))
