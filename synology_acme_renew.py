# -*- coding: utf-8 -*-

"""
Usage:
   - acme.sh must be installed!
   - DNS challenge(https://github.com/Neilpang/acme.sh/wiki/dnsapi):
     `env DOMAIN=xxx DNS_PROVIDER=dns_XX DNS_API_KEY=XXX python synology_acme_renew.py`


NOTE:
  Tested device is DS918+(DSM 6.2.2-24922 Update 3)
  In case of things goes wrong, recover it manually:
    1. acme.sh will backup the certificates to ~/.acme.sh/<domain>/backup/*.pem, so we can use it to recover
    2. rename acme.sh generated certificates like this: *.*->*.pem, key.pem->private.pem, ca.pem -> chain.pem


Functions of this script:
    1. Backup all certificates: `/usr/syno/etc/certificate/_archive/<DEFAULT>/*.pem` -> `/tmp/acme-renew/certs-<NOW>-backup`
    2. Issue certificates with acme.sh, new certs will be generated at `/tmp/acme-renew/certs-<NOW>-new`
    3. Update certificates: replace the certificates described in `/usr/syno/etc/certificate/_archive/INFO`,
        - Replace all certificates under `_archive/<DEFAULT>`
        - Replace all certificates under `system/default`
        - Replace all certificates under `ReverseProxy`
        - Replace all certificates under `smbftpd/ftpd`
        - All services with `"isPkg": true` are ignored
            - except VPNCenter/OpenVPN: `/usr/syno/etc/packages/VPNCenter/openvpn/keys`
    4. Reload nginx
    5. Rollback if one of the above steps failed
    6. Clean up
""" # noqa

import os
import sys
import shutil
import glob
import json
import subprocess
import tempfile
import os.path as pathlib
from datetime import datetime

ACMESH_PATH = "/usr/local/share/acme.sh/acme.sh"
CERTS_ROOT_PATH = "/usr/syno/etc/certificate/"
OPENVPN_KEYS_PATH = "/usr/syno/etc/packages/VPNCenter/openvpn/keys"
CERT_FILE = "cert.pem"
KEY_FILE = "privkey.pem"
FULLCHAIN_FILE = "fullchain.pem"
CA_FILE = "ca.crt"
NOW = "{0:%Y-%m-%d_%H%M%S}".format(datetime.now())
CERTS_BACKUP_PATH = pathlib.join(
    tempfile.gettempdir(), "acme-renew/certs-{}-backup".format(NOW)
)
CERTS_NEW_PATH = pathlib.join(
    tempfile.gettempdir(), "acme-renew/certs-{}-new".format(NOW)
)
VERBOSE = True


def _log(fmt, depth=0, *args):  # For Py2 compatible..
    if VERBOSE:
        fmt = "  "*depth + "> " + fmt
        print(fmt.format(*args))


LOG = lambda fmt, *args: _log(fmt, 0, *args)  # noqa
LOG1 = lambda fmt, *args: _log(fmt, 1, *args)  # noqa


def _default_name(certs_root_path=CERTS_ROOT_PATH):
    archive_path = pathlib.join(certs_root_path, "_archive")
    with open(pathlib.join(archive_path, "DEFAULT")) as f:
        return f.read().strip(" \n")


def backup(
    certs_backup_path=CERTS_BACKUP_PATH, certs_root_path=CERTS_ROOT_PATH
):
    archive_path = pathlib.join(certs_root_path, "_archive")
    default_dir = _default_name(certs_root_path)
    default_archive_path = pathlib.join(archive_path, default_dir)
    LOG("BACKUP: {} -> {}", default_archive_path, certs_backup_path)

    _mkdirs(certs_backup_path)
    certs = glob.glob(pathlib.join(default_archive_path, "*.pem"))
    for cert in certs:
        LOG1("copy: {}", cert)
        shutil.copy(cert, certs_backup_path)
    return certs_backup_path


def issue_certs(
    domain,
    dns_provider,
    acmesh_path=ACMESH_PATH,
    certs_new_path=CERTS_NEW_PATH
):
    LOG("ISSUE_CERTS: {} -> {}", domain, certs_new_path)
    with_dns_provider = ""
    if dns_provider:
        with_dns_provider = '--dns "{}"'.format(dns_provider)
    renew_cmd = r"""{acmesh_path} --issue \
    {with_dns_provider} -d "{domain}" \
    --cert-file "{output_dir}/{cert_file}" \
    --key-file "{output_dir}/{key_file}" \
    --fullchain-file "{output_dir}/{fullchain_file}" \
    --capath "{output_dir}/chain.pem" \
    --ca-file "{output_dir}/{ca_file}" \
    --dnssleep 180 --force # --debug"""
    _mkdirs(certs_new_path)
    _exec_cmd(
        renew_cmd.format(
            acmesh_path=acmesh_path,
            domain=domain,
            with_dns_provider=with_dns_provider,
            output_dir=certs_new_path,
            cert_file=CERT_FILE,
            key_file=KEY_FILE,
            fullchain_file=FULLCHAIN_FILE,
            ca_file=CA_FILE,
        )
    )
    return certs_new_path


def update_certs(new_certs_path, certs_root_path=CERTS_ROOT_PATH):
    LOG("UPDATE_CERTS: <non-packages>")
    new_certs = glob.glob(pathlib.join(new_certs_path, "*.pem"))

    certs_info_path = pathlib.join(certs_root_path, "_archive/INFO")
    with open(certs_info_path) as f:
        certs_info = json.load(f)
    default_dir = _default_name(certs_root_path)
    archive_path = pathlib.join(certs_root_path, "_archive")
    default_archive_path = pathlib.join(archive_path, default_dir)

    LOG1("update [{}]: {}", "DEFAULT", default_archive_path)
    _update_certs(new_certs, default_archive_path)

    for service in certs_info[default_dir]["services"]:
        target_path = pathlib.join(
            certs_root_path, service["subscriber"], service["service"]
        )
        if service["isPkg"]:
            #  LOG1("ignore [{}]: {}", service["display_name"], target_path)
            continue

        LOG1("update [{}]: {}", service["display_name"], target_path)
        _update_certs(new_certs, target_path)


def _update_certs(new_certs, target_path):
    old_certs = glob.glob(pathlib.join(target_path, "*.pem"))
    for cert in old_certs:
        os.remove(cert)
    for cert in new_certs:
        shutil.copy(cert, target_path)


def update_certs_for_openvpn(
    new_certs_path,
    openvpn_keys_path=OPENVPN_KEYS_PATH,
):
    if not pathlib.isdir(openvpn_keys_path):
        return False
    LOG("UPDATE_CERTS: VPNCenter")
    old_certs = glob.glob(pathlib.join(openvpn_keys_path, "*"))
    for cert in old_certs:
        try:
            os.remove(cert)
        except OSError:
            pass

    LOG1("update [OpenVPN]: {}", openvpn_keys_path)
    # FIXME: the mapping..
    for src, dest in {
        CERT_FILE: "server.crt",
        KEY_FILE: "server.key",
        FULLCHAIN_FILE: "ca_bundle.crt",
        CA_FILE: "ca.crt",
    }.items():
        shutil.copy(
            pathlib.join(new_certs_path, src),
            pathlib.join(openvpn_keys_path, dest),
        )
    return True


def reload(service):
    LOG("RELOAD: {}", service)
    control_service("reload", service)


def restart(service):
    LOG("RESTART: {}", service)
    control_service("restart", service)


def control_service(action, service):
    cmd = "/usr/syno/sbin/synoservicectl --{} {}".format(action, service)
    _exec_cmd(cmd)


def cleanup(paths):
    LOG("CLEANUP: {}", paths)
    for path in paths:
        LOG1("cleanup: {}", path)
        try:
            shutil.rmtree(path)
        except OSError:
            pass


def _exec_cmd(cmd, env=None):
    LOG1("EXEC: {}", cmd)
    env = env or {}
    env.update(os.environ)
    p = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )
    msg = p.stdout.read()
    p.stdout.close()  # Avoid resource leak.
    if p.wait() != 0:
        raise Exception(msg)


def _mkdirs(path):
    try:
        os.removedirs(path)
    except OSError:
        pass
    os.makedirs(path)


if __name__ == "__main__":
    domain = os.getenv("DOMAIN")
    acmesh_path = os.getenv("ACMESH_PATH", default=ACMESH_PATH)
    dns_provider = os.getenv("DNS_PROVIDER")
    if not domain:
        sys.exit(
            "DOMAIN required!\n"
            "If you using DNS-challenge, DNS_PROVIDER and other ENVs also"
            " required, see https://github.com/Neilpang/acme.sh/wiki/dnsapi"
        )

    tmp_paths = []
    try:
        certs_backup_path = backup()
        tmp_paths.append(certs_backup_path)
        certs_new_path = issue_certs(
            domain, dns_provider, acmesh_path=acmesh_path
        )
        tmp_paths.append(certs_new_path)

        update_certs(certs_new_path)
        reload("nginx")

        if update_certs_for_openvpn(certs_new_path):
            restart("pkgctl-VPNCenter")
    except Exception:
        update_certs(certs_backup_path)  # Rollback..
        raise
    finally:
        cleanup(tmp_paths)
