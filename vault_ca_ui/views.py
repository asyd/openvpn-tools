import datetime

import hvac
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from flask import current_app as app
from flask import render_template, Response, Blueprint, redirect, url_for
from .extensions import cache

root = Blueprint('root', __name__)


@root.route('/')
def index():
    """
    List certificates authorities as defined in config file
    """
    return render_template('index.html', cas=app.config['CAS'])


@root.route('/ca/<ca>/<serial>/<cn>')
def get_certificate(ca, serial, cn):
    vault = hvac.Client(app.config['VAULT_ADDR'])
    vault.token = app.config['VAULT_TOKEN']
    assert vault.is_authenticated()

    certificate = vault.read('{}/cert/{}'.format(ca, serial))

    return Response(
        certificate['data']['certificate'],
        mimetype='application/x-pem-file',
        headers={'Content-Disposition': 'attachment;filename={}.pem'.format(cn)}
    )


@root.route('/ca/<ca>')
@cache.cached(timeout=60)
def ca_list_certificates(ca):
    """
    Display the list of certificates for the given CA id.
    :param ca: CA Identifier
    """
    vault = hvac.Client(app.config['VAULT_ADDR'])
    vault.token = app.config['VAULT_TOKEN']
    assert vault.is_authenticated()

    now = datetime.datetime.now()

    output = []
    # Get list of certificate serial numbers
    for cert_serial in vault.list('%s/certs' % ca)['data']['keys']:
        # Get certificate entry
        record = vault.read('%s/cert/%s' % (ca, cert_serial))
        # Read and parse certificate from PEM
        cert = x509.load_pem_x509_certificate(
            record['data']['certificate'].encode(),
            default_backend())  # type: x509.Certificate
        # Add fields to certificate details
        status = 'valid'

        if (cert.not_valid_after - now).total_seconds() < 0:
            status = 'expired'

        if record['data']['revocation_time'] > 0:
            status = 'revoked'

        output.append({
            'serial_number': cert_serial,
            'common_name': cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
            'start_date': cert.not_valid_before,
            'end_date': cert.not_valid_after,
            'revocation_time': record['data']['revocation_time'],
            'revocation_date': datetime.datetime.fromtimestamp(record['data']['revocation_time']),
            'status': status
        })

    return render_template('list.html', certs=output, ca=ca)


@root.route('/cert/revoke/<ca>/<serial>')
def revoke_cert(ca, serial):
    """
    Revoke the certificate from the given CA, invalid CA cache, and redirect
    to the the list of certificates of the given CA.
    
    :param ca: The Certificate Authority identifier
    :param serial: Certificate serial number in hex string (ab:cd:..)
    :return: Redirect to the list of certificates of the given CA
    """
    vault = hvac.Client(app.config['VAULT_ADDR'])
    vault.token = app.config['VAULT_TOKEN']
    assert vault.is_authenticated()

    vault.write('/{}/revoke'.format(ca),
                serial_number=serial)

    # Invalid cache
    # Return to list
    return redirect(url_for('root.ca_list_certificates', ca=ca))
