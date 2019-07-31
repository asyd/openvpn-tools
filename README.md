# Description

This is a collection of script to manage OpenVPN's users based on hashicorp's vault. You can create
new users using a script, see current users and revoke them with the WebUI.

# Installation

  * Clone the repo
  * Run `pipenv install`, or create a new virtualenv add install dependencies from `requirements.txt`
  * Ensure `VAULT_ADDR` is defined 
  * Ensure you have a vault token in `$HOME/.vault-token` with enough privileges to access CAs  
  * Create a `ca_tree.yaml` based on `ca_tree.sample.yaml`
  * Create a template on `templates` directory (see example)
    * Update `<ca>` sections to put the certificate authority chain
    * Special keys `{{ key }}` and `{{ cert }}` will be replaced by new user certificate and key


# Usage

## Create a new user and its corresponding ovpn file

```
mkdir -p users
cd users
pipenv run python ../create_user_cert.py --template ../templates/base.ovpn ca_users vpn_access asyd
```

Where `vpn_access` is a profile in hashicorp`s vault.

## Run the webapp

```
pipenv run python run_app.py
```

## Revocation check

Copy the `script/check-revocation-status.py` to your OpenVPN server. Set `VAULT_ADDR`, and add this line
to your openvpn configuration:

```
tls-verify scripts/check-revocation-status.py
```
