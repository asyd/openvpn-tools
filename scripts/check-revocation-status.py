#!/usr/bin/env python3

import requests
import argparse
import os
import logging
import sys

VAULT_ADDR = 'http://localhost:8200'

DN_MAPPING = {
    'Root CA': 'ca_root',
    'Users CA': 'ca_users',
}


def main(ca_id, cert_serial):
    if ca_id is None or cert_serial is None:
        logging.error("Invalid CA id: {} or serial number: {}".format(ca_id, cert_serial))
        return False

    req = requests.get("{}/v1/{}/cert/{}".format(VAULT_ADDR, ca_id, cert_serial))
    if req.status_code == 200:
        revocation_time = int(req.json()['data']['revocation_time'])
        if revocation_time > 0:
            return False
    else:
        return False

    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Check status for given certificate')
    parser.add_argument('--log-level', default=logging.WARN, help='logger module level to use')
    parser.add_argument('depth', type=int, help='Depth in certificate chain')
    parser.add_argument('dn', help='DN of the certificate. This argument IS NOT USED')
    args = parser.parse_args()

    logging.basicConfig(level=args.log_level)

    logging.debug("Arguments: depth ({}), X509_NAME_online ({})".format(args.depth, args.dn))
    ca_name = os.getenv('X509_{}_CN'.format(args.depth), False)

    cert_serial = os.getenv('tls_serial_hex_{}'.format(args.depth), None)
    # We need the identifier of the issuer, not of of the subject.
    if args.depth == 0:
        args.depth = 1
    ca_id = DN_MAPPING[os.getenv('X509_%s_CN' % args.depth, False)]
    logging.debug("X509 CA Name: {}, X509 CA id: {}".format(ca_name, ca_id))
    if ca_id is None or cert_serial is None:
        logging.error("Either ca_id ({}) or cert_serial ({}) is None".format(ca_id, cert_serial))
        sys.exit(255)
    if not main(ca_id, cert_serial):
        logging.error("Certificate {} is revoked".format(cert_serial))
        sys.exit(1)
