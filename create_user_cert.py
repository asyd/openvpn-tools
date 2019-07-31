#!/usr/bin/env python

import argparse
import logging
import os
import sys

import hvac
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from jinja2 import Template


def main(args):
    # Create vault client
    client = hvac.Client(os.getenv('VAULT_ADDR'))
    logging.info("Use vault: {}".format(os.getenv('VAULT_ADDR')))
    with open('%s/.vault-token' % os.path.expanduser("~"), 'r') as f:
        client.token = f.readline()

    assert client.is_authenticated()

    # Get list of certificates to check if common name already exists
    for cert_serial in client.list('%s/certs' % args.ca)['data']['keys']:
        record = client.read('%s/cert/%s' % (args.ca, cert_serial))
        cert = x509.load_pem_x509_certificate(record['data']['certificate'].encode(), default_backend())
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        if args.cn == cn:
            if not args.force:
                logging.error("There is already a certificate with this common name")
                sys.exit(1)
            else:
                logging.warning("There is already a certificate with this common name")

    # Issue the certificate
    result = client.write('%s/issue/%s' % (args.ca, args.role),
                          common_name=args.cn,
                          ttl='8760h')

    # Write result
    with open('%s_cert.pem' % args.cn, 'w') as o:
        o.write(result['data']['certificate'])
    with open('%s_key.pem' % args.cn, 'w') as o:
        o.write(result['data']['private_key'])

    # Generate file from template if provided
    if args.template is not None:
        # Open template
        with open(args.template, 'r') as fh:
            template = Template(''.join(fh.readlines()))

        with open("%s%s" % (args.cn, os.path.splitext(args.template)[1]), 'w') as fh:
            fh.write(template.render(
                cert=result['data']['certificate'],
                key=result['data']['private_key']
            ))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create a certificate')
    parser.add_argument('-f', '--force',
                        default=False,
                        action='store_true',
                        help='Issue certificate even if CN already exist')
    parser.add_argument('--template',
                        default=None,
                        help='Create a file from given jinja2 template')
    parser.add_argument('ca', help='CA Identifier')
    parser.add_argument('role', help='CA role')
    parser.add_argument('cn', help='Common name')
    args = parser.parse_args()
    print(args)
    main(args)
