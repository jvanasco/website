"""
# Overview

This file is used to generate `certificates.json`

# Usage

in this directory, execute the following command:

    python certificates_build.py

# Requirements

This script requires the following packages from PyPi, however these packages
are required by Certbot - so this should run on a system/virtualenv that has
Certbot installed

    OpenSSL
    requests

# What this script does:

This script loads the HUMAN CURATED FILE `_certificate_data.json` and uses it
to generate the machine readable file `certificates.json`.

The file `_certificate_data.json` contains core information about the various
Root Certificates in the LetsEncrypt trust chains.

This script:
   * ensures all the Certificate files are online
   * ensures no duplication of Certificates

The input is `_certificate_data.json`, which is built on this structure:

    {
      "lastmod": "2020-12-07",
      "certificates": [
        <CERTIFICATE_NODE>,
        <CERTIFICATE_NODE>,
        <CERTIFICATE_NODE>,
       ]
    }

An example <CERTIFICATE_NODE> is required to have this information:

	{
	  "_name": "ISRG Root X1",
	  "crtsh": "https://crt.sh/?id=9314791",
	  "der": "https://letsencrypt.org/certs/isrgrootx1.der",
	  "pem": "https://letsencrypt.org/certs/isrgrootx1.pem",
	  "signed_by": "https://letsencrypt.org/certs/isrgrootx1.pem",
	  "status": "active",
	  "txt": "https://letsencrypt.org/certs/isrgrootx1.txt",
	  "type": "root"
	},

The fields are:

    _name: used for organizing within the document
    type: "root" or "intermediate"
    status: active, retired, backup, upcoming
    URLS:
        crtsh: URL of the certificate on crtsh
        der: URL of the DER encoded certificate
        pem: URL of the PEM encoded certificate
        txt: URL of the TEXT encoded certificate
    	signed_by: URL of the PEM encoded certificate which signed this certificate (upchain)
    	cross_signed_variant_of: URL of the PEM encoded certificate signed by a different authority


The output file is a JSON document with this structure:

    {
      "lastmod": "2020-12-07",
      "lastmod_sources": "2020-12-07",
      "certificates": [
        <CERTIFICATE_NODE>,
        <CERTIFICATE_NODE>,
        <CERTIFICATE_NODE>,
       ]
    }

In which:

    * lastmod - when the file was last modified
    * lastmod_sources - when the source file was last modified (_certificate_data.json)

An example <CERTIFICATE_NODE> is generated to have this information:

    {
      "certificate": {
        "algorithm": "RSA",
        "bits": 4096,
        "cn": "ISRG Root X1",
        "notAfter": "20350604110438Z",
        "notBefore": "20150604110438Z",
        "o": "Internet Security Research Group",
        "selfsigned": true
      },
      "issuer": {
        "cn": "ISRG Root X1",
        "o": "Internet Security Research Group",
        "url_pem": "https://letsencrypt.org/certs/isrgrootx1.pem"
      },
      "status": "active",
      "type": "root",
      "urls": {
        "crtsh": "https://crt.sh/?id=9314791",
        "der": "https://letsencrypt.org/certs/isrgrootx1.der",
        "pem": "https://letsencrypt.org/certs/isrgrootx1.pem",
        "txt": "https://letsencrypt.org/certs/isrgrootx1.txt"
      }
    },

In the above example, the URLS were copied over from the input, but the remaining
information was extracted from the certificates.
"""

# stdlib
import datetime
import json
import pprint

# pypi
from OpenSSL import crypto as openssl_crypto
import requests


def key_type(key):
    cert_type = key.type()
    if cert_type == openssl_crypto.TYPE_RSA:
        return "RSA"
    elif cert_type == openssl_crypto.TYPE_EC:
        return "EC"
    elif cert_type == openssl_crypto.TYPE_DSA:
        return "DSA"
    return None


# load the input file
cert_sources = None
cert_sources_lastmod = None
with open("_certificate_data.json", "r") as fp:
    _data = json.loads(fp.read())
    cert_sources = _data["certificates"]
    cert_sources_lastmod = _data["lastmod"]

# our output list
CERTS_FORMATTED = []

# track unique URLS
UNIQUE_URL_TYPES = ("crtsh", "der", "pem", "txt")
URLS_SEEN = {_type: [] for _type in UNIQUE_URL_TYPES}

# TODO: migrate this to an ENVIRONMENT variable
CHECK_ALTERNATE_URLS = True


for cert_payload in cert_sources:

    # lightweight error checking
    # these are unique!
    for _url_type in UNIQUE_URL_TYPES:
        _unique_url = cert_payload[_url_type]
        assert _unique_url not in URLS_SEEN[_url_type]
        URLS_SEEN[_url_type].append(_unique_url)

    url = cert_payload["pem"]
    print("processing: %s" % url)
    r_pem = requests.get(url)
    assert r_pem.status_code == 200
    cert_pem = r_pem.text
    cert_object = openssl_crypto.load_certificate(openssl_crypto.FILETYPE_PEM, cert_pem)

    # the openssl crypto interface uses CAPS
    issuer = dict(cert_object.get_issuer().get_components())
    subject = dict(cert_object.get_subject().get_components())
    cert_pubkey = cert_object.get_pubkey()

    if CHECK_ALTERNATE_URLS:
        # check to ensure this is a valid url
        r_1 = requests.get(cert_payload["crtsh"])
        assert r_1.status_code == 200

        # ensure the txt and der formats are live
        # TODO: in a future version, ensure they are equal to the active cert
        r_txt = requests.get(cert_payload["txt"])
        assert r_txt.status_code == 200
        r_der = requests.get(cert_payload["der"])
        assert r_der.status_code == 200

    # this is the output payload
    cert_data = {
        "type": cert_payload["type"],
        "status": cert_payload["status"],
        "urls": {
            "crtsh": cert_payload["crtsh"],
            "txt": cert_payload["txt"],
            "pem": cert_payload["pem"],
            "der": cert_payload["der"],
        },
        "certificate": {
            "o": subject["O"],
            "cn": subject["CN"],
            "notAfter": cert_object.get_notAfter(),
            "notBefore": cert_object.get_notBefore(),
            "algorithm": key_type(cert_pubkey),
            "bits": cert_pubkey.bits(),
            "selfsigned": True
            if cert_payload["signed_by"] == cert_payload["pem"]
            else False,
        },
        "issuer": {
            "o": issuer["O"],
            "cn": issuer["CN"],
            "url_pem": cert_payload["signed_by"],
        },
    }
    CERTS_FORMATTED.append(cert_data)


# format our JSON payload
_today = datetime.datetime.today()
CERTS_JSON = {
    "lastmod": _today.strftime("%Y-%0m-%0d"),
    "lastmod_sources": cert_sources_lastmod,
    "certificates": CERTS_FORMATTED,
}

# write our JSON payload
with open("certificates.json", "w") as fp:
    fp.write(json.dumps(CERTS_JSON, sort_keys=True, indent=2))
