#!/usr/bin/env python3

import argparse
import base64
import os.path
import re
import secrets
import sys
from hashlib import sha3_256
from os import path

from pyasn1.codec.der.encoder import encode
from pyasn1.type import univ
from pyasn1_alt_modules import rfc2985, rfc2986, rfc8410, rfc5280

from onionmaker import ed25519

OID_CABF_CA_SIGNING_NONCE = univ.ObjectIdentifier('2.23.140.41')
OID_CABF_CA_APPLICANT_NONCE = univ.ObjectIdentifier('2.23.140.42')

APPLICANT_SIGNING_NONCE_OCTET_COUNT = 16
PUBLIC_KEY_FILENAME = 'hs_ed25519_public_key'
PRIVATE_KEY_FILENAME = 'hs_ed25519_secret_key'

RANDOM_VALUE_REGEX = re.compile(r'^[a-z0-9_]{32}$', re.IGNORECASE)


def _validate_random_value(value):
    if RANDOM_VALUE_REGEX.match(value):
        return value
    else:
        raise ValueError(f'Invalid Random Value syntax: random value must be 32 alphanumeric characters')


def _validate_service_dir(dir_path):
    real_dir_path = os.path.realpath(dir_path)
    if not path.exists(real_dir_path):
        raise ValueError(f'Specified directory "{dir_path}" does not exist')

    if not path.isdir(real_dir_path):
        raise ValueError(f'Specified directory "{dir_path}" is not a directory')

    def validate_path_exists(filename, file_type):
        file_path = path.join(dir_path, filename)
        if not path.exists(file_path):
            raise ValueError(f'{file_type.title()} file does not exist at "{file_path}"')

    validate_path_exists(PUBLIC_KEY_FILENAME, 'Public key')
    validate_path_exists(PRIVATE_KEY_FILENAME, 'Private key')

    return dir_path


def _read_key_file(dir_path, filename, key_type):
    key_path = path.join(dir_path, filename)

    with open(key_path, 'rb') as f:
        file_octets = f.read()

        if not file_octets.startswith(b'== ed25519v1-' + key_type.encode('us-ascii') + b': type0 ==\x00\x00\x00'):
            raise ValueError(f'"{key_path}" does not start with magic bytes')

        key_octets = file_octets[32:]

        if key_type == 'secret':
            if len(key_octets) != 64:
                raise ValueError('Invalid private key length')
        else:
            if len(key_octets) != 32:
                raise ValueError('Invalid public key length')

        return key_octets


def _generate_applicant_signing_nonce():
    return secrets.token_hex(APPLICANT_SIGNING_NONCE_OCTET_COUNT)


def _create_octet_string_attribute(oid, value_str):
    attr = rfc2986.Attribute()

    attr['type'] = oid
    attr['values'].append(univ.OctetString(value_str.encode('us-ascii')))

    return attr


def _create_onion_domain_name(public_key_octets):
    h = sha3_256()
    h.update(b'.onion checksum' + public_key_octets + b'\x03')
    checksum = h.digest()[:2]

    second_level_domain_name = base64.b32encode(public_key_octets + checksum + b'\x03').decode('us-ascii').lower()

    return f'{second_level_domain_name}.onion'


def _create_san_extension_request(public_key_octets):
    domain_name = _create_onion_domain_name(public_key_octets)

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


def _create_certification_request_info(public_key_octets, ca_signing_nonce_str, applicant_signing_nonce_str):
    cri = rfc2986.CertificationRequestInfo()
    cri['version'] = univ.Integer(0)

    cri['subject'].setComponentByName('rdnSequence', rfc2986.RDNSequence())

    spki = rfc2986.SubjectPublicKeyInfo()
    algo_id = rfc2986.AlgorithmIdentifier()
    algo_id['algorithm'] = rfc8410.id_Ed25519

    spki['algorithm'] = algo_id

    spki['subjectPublicKey'] = univ.BitString.fromHexString(public_key_octets.hex())
    cri['subjectPKInfo'] = spki

    cri['attributes'].append(_create_octet_string_attribute(OID_CABF_CA_SIGNING_NONCE, ca_signing_nonce_str))
    cri['attributes'].append(_create_octet_string_attribute(OID_CABF_CA_APPLICANT_NONCE, applicant_signing_nonce_str))
    cri['attributes'].append(_create_san_extension_request(public_key_octets))

    return cri


def _sign_certification_request(private_key_octets, certification_request_info):
    cri_der = encode(certification_request_info)

    public_key_octets = certification_request_info['subjectPKInfo']['subjectPublicKey'].asOctets()

    signature_hex = ed25519.sign(public_key_octets, private_key_octets, cri_der).hex()

    csr = rfc2986.CertificationRequest()
    csr['certificationRequestInfo'] = certification_request_info
    csr['signatureAlgorithm'] = certification_request_info['subjectPKInfo']['algorithm']
    csr['signature'] = univ.BitString.fromHexString(signature_hex)

    return csr


def _der_to_pem(der):
    b64 = base64.b64encode(der).decode('us-ascii')
    pem = '-----BEGIN CERTIFICATE REQUEST-----\n'

    for i in range(0, len(b64), 64):
        pem += b64[i:i + 64] + '\n'

    pem += '-----END CERTIFICATE REQUEST-----\n'

    return pem


def _validate_arg(validator, value):
    try:
        return validator(value)
    except ValueError as e:
        print(e, file=sys.stderr)

        exit(1)


def _main():
    parser = argparse.ArgumentParser(description='Create CSRs suitable for validation of Tor v3 Onion Domain Names '
                                                 'according to Appendix B of the CA/Browser Forum Baseline '
                                                 'Requirements', prog='onionmaker')
    parser.add_argument('random_value', help='The Random Value supplied by the CA')
    parser.add_argument('hidden_service_dir', nargs='?',
                        default='/var/lib/tor/hidden_service', help='The directory for the Tor v3 service')

    args = parser.parse_args()

    _validate_arg(_validate_random_value, args.random_value)
    _validate_arg(_validate_service_dir, args.hidden_service_dir)

    private_key_octets = _read_key_file(args.hidden_service_dir, PRIVATE_KEY_FILENAME, 'secret')
    public_key_octets = _read_key_file(args.hidden_service_dir, PUBLIC_KEY_FILENAME, 'public')

    certification_request_info = _create_certification_request_info(public_key_octets, args.random_value,
                                                                    _generate_applicant_signing_nonce())

    csr_asn1 = _sign_certification_request(private_key_octets, certification_request_info)

    csr_der = encode(csr_asn1)

    print(_der_to_pem(csr_der), end='')


if __name__ == '__main__':
    _main()
