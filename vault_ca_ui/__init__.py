import os
import yaml
from flask_appconfig import AppConfig
from flask_bootstrap import Bootstrap
from flask import Flask
from .views import root
from .extensions import cache


def create_app(config_file=None):
    """
    Create application
    :param config_file: Not used at the moment
    :return: flask app instance
    """
    app = Flask('vault_ca_ui')
    # Read configuration from file
    AppConfig(app, config_file)

    # Enable bootstrap
    Bootstrap(app)

    # Register main controller
    app.register_blueprint(root)

    # Don't use CDN
    app.config['BOOTSTRAP_SERVE_LOCAL'] = True

    # Read vault token
    with open('%s/.vault-token' % os.path.expanduser("~"), 'r') as f:
        app.config['VAULT_TOKEN'] = f.readline()

    # Set vault url
    app.config['VAULT_ADDR'] = os.getenv('VAULT_ADDR')

    # Read certificate authorities tree
    with open('ca_tree.yaml', 'r') as fh:
        app.config['CAS'] = yaml.load(fh, Loader=yaml.Loader)

    # Enable cache
    cache.init_app(app, config={'CACHE_TYPE': 'simple'})

    return app
