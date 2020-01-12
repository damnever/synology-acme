Renew Synology's certificates with [acme.sh](https://github.com/Neilpang/acme.sh). It does backup and rollback things automatically.

DNS challenge works as expected but API challenge may not be working since 80/443 has been banned by XXX in China.

```
# Install acme.sh
curl https://get.acme.sh | sh

# Download this script
curl https://raw.githubusercontent.com/damnever/synology-acme/master/synology_acme_renew.py -o acme-renew.py

# Example usage for DNS challenge(https://github.com/Neilpang/acme.sh/wiki/dnsapi):
# ACMESH_PATH=/usr/local/share/acme.sh/acme.sh
env DOMAIN=*.X.X DNS_PROVIDER=dns_gd GD_Key=abc GD_Secret=xyz python acme-renew.py
```
