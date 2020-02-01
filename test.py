# -*- coding: utf-8 -*-

# TODO: bad testcases

import unittest
import tempfile
import json
import shutil
import os.path as pathlib

import synology_acme_renew

_INFO_CONTENT = """{
  "TestXX" : {
    "desc" : "Test Certificate",
    "services" : [
      {
        "display_name" : "FTPS",
        "isPkg" : false,
        "owner" : "root",
        "service" : "ftpd",
        "subscriber" : "smbftpd"
      },
      {
        "display_name" : "DSM Desktop Service",
        "display_name_i18n" : "common:web_desktop",
        "isPkg" : false,
        "owner" : "root",
        "service" : "default",
        "subscriber" : "system"
      },
      {
        "display_name" : "Log Receiving",
        "display_name_i18n" : "helptoc:logcenter_server",
        "isPkg" : true,
        "owner" : "root",
        "service" : "pkg-LogCenter",
        "subscriber" : "LogCenter"
      },
      {
        "display_name" : "VPNServer",
        "display_name_i18n" : "SYNO.SDS.VPN.Instance:app:app_name",
        "isPkg" : true,
        "owner" : "root",
        "service" : "OpenVPN",
        "subscriber" : "VPNCenter"
      },
      {
        "display_name" : "Synology Drive Server",
        "display_name_i18n" : "SYNO.SDS.Drive.Application:app:pkg_name",
        "isPkg" : true,
        "owner" : "SynologyDrive",
        "service" : "SynologyDrive",
        "subscriber" : "SynologyDrive"
      },
      {
        "display_name" : "Replication Service",
        "display_name_i18n" : "app:displayname",
        "isPkg" : true,
        "owner" : "root",
        "service" : "snapshot_receiver",
        "subscriber" : "ReplicationService"
      },
      {
        "display_name" : "1.example.test",
        "isPkg" : false,
        "owner" : "root",
        "service" : "fc0d377f-d266-4635-9f1d-a7ee46dda720",
        "subscriber" : "ReverseProxy"
      },
      {
        "display_name" : "2.example.test",
        "isPkg" : false,
        "owner" : "root",
        "service" : "6ff5d885-c6fb-402d-b8fb-5f3b6a415dc6",
        "subscriber" : "ReverseProxy"
      },
      {
        "display_name" : "3.example.test",
        "isPkg" : false,
        "owner" : "root",
        "service" : "b7af6232-f986-4910-85b7-622a10b7424d",
        "subscriber" : "ReverseProxy"
      }
    ]
  }
}"""


class Test(unittest.TestCase):
    def _touch_pems(self, directory, content="OLD"):
        for name in [
            "cert.pem", "chain.pem", "fullchain.pem", "privkey.pem", "ca.crt"
        ]:
            with open(pathlib.join(directory, name), "w+") as f:
                f.write(content)

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="synology-acme-renew-test")
        self.certs_root_dir = pathlib.join(self.tmpdir, "certificate")
        archive_path = pathlib.join(self.certs_root_dir, "_archive")
        synology_acme_renew._mkdirs(pathlib.join(archive_path, "TestXX"))
        self._touch_pems(pathlib.join(archive_path, "TestXX"))
        with open(pathlib.join(archive_path, "DEFAULT"), "w+") as f:
            f.write("TestXX")
        with open(pathlib.join(archive_path, "INFO"), "w+") as f:
            f.write(_INFO_CONTENT)
        self.info = json.loads(_INFO_CONTENT)
        for service in self.info["TestXX"]["services"]:
            if service["isPkg"]:
                continue
            subpath = pathlib.join(
                self.certs_root_dir, service["subscriber"], service["service"]
            )
            synology_acme_renew._mkdirs(subpath)
            self._touch_pems(subpath)

        self.openvpn_keys_dir = pathlib.join(
            self.tmpdir, "packages/VPNCenter/openvpn/keys"
        )
        synology_acme_renew._mkdirs(self.openvpn_keys_dir)

    def tearDown(self):
        if hasattr(self, 'tmpdir'):
            shutil.rmtree(self.tmpdir)

    _NORMAL_CERT_NAMES = [
        "cert.pem", "privkey.pem", "chain.pem", "fullchain.pem"
    ]
    _OPENVPN_CERT_NAMES = [
        "server.crt", "server.key", "ca_bundle.crt", "ca.crt"
    ]

    def _assert_certs(
        self, directory, content="OLD", certs_names=_NORMAL_CERT_NAMES
    ):
        for name in certs_names:
            with open(pathlib.join(directory, name), "r") as f:
                self.assertEqual(content, f.read())

    def test_backup(self):
        backup_path = pathlib.join(self.certs_root_dir, "BACKUP")
        synology_acme_renew.backup(backup_path, self.certs_root_dir)
        self._assert_certs(backup_path)

    def test_update_certs(self):
        new_path = pathlib.join(self.certs_root_dir, "NEW")
        synology_acme_renew._mkdirs(new_path)
        self._touch_pems(new_path, content="NEW")
        synology_acme_renew.update_certs(new_path, self.certs_root_dir)
        self._assert_certs(
            pathlib.join(self.certs_root_dir, "_archive/TestXX"), "NEW"
        )
        for service in self.info["TestXX"]["services"]:
            if service["isPkg"]:
                continue
            subpath = pathlib.join(
                self.certs_root_dir, service["subscriber"], service["service"]
            )
            self._assert_certs(subpath, "NEW")

        synology_acme_renew.update_certs_for_openvpn(
            new_path, self.openvpn_keys_dir
        )
        self._assert_certs(
            self.openvpn_keys_dir, "NEW", self._OPENVPN_CERT_NAMES
        )

    def test_cleanup(self):
        directories = [
            pathlib.join(self.certs_root_dir, "a"),
            pathlib.join(self.certs_root_dir, "b")
        ]
        for d in directories:
            synology_acme_renew._mkdirs(d)
            open(pathlib.join(d, "content"), "w+").close()
        synology_acme_renew.cleanup(directories)
        for d in directories:
            self.assertFalse(pathlib.exists(d))

    def test__exec_cmd(self):
        tmp_file = pathlib.join(self.certs_root_dir, "EXEC")
        synology_acme_renew._exec_cmd("touch " + tmp_file)
        self.assertTrue(pathlib.isfile(tmp_file))


if __name__ == '__main__':
    unittest.main()
