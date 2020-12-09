"""
{
    "lastmod": "2020-12-08",
    "certificates": [
        {
          "displayname": "ISRG Root X1",
          "type": "root",
          "status": "active",
		  "urls": [
			  "crtsh": "https://crt.sh/?id=9314791",
			  "txt": "https://letsencrypt.org/certs/isrgrootx1.txt",
			  "pem": "https://letsencrypt.org/certs/isrgrootx1.pem",
			  "der": "https://letsencrypt.org/certs/isrgrootx1.der",
			],
			"data": [
			  "o": "Internet Security Research Group",
			  "cn": "ISRG Root X1",
	          "notAfter": "20350604110438Z",
    	      "notBefore": "20150604110438Z",
			  "algorithm": "RSA"
			  "bits": 4096,
    	    ],
        },
    ]
}

"""

# stdlib
import datetime
import requests
import json
import pprint
import pdb

# pypi
from OpenSSL import crypto as openssl_crypto
from Crypto.Util import asn1


def key_type(key):
    cert_type = key.type()
    if cert_type == openssl_crypto.TYPE_RSA:
        return "RSA"
    elif cert_type == openssl_crypto.TYPE_EC:
        return "EC"
    elif cert_type == openssl_crypto.TYPE_DSA:
        return "DSA"
    return None

CHECK_ALTERNATE_URLS = True
cert_sources = [
    {
    "_name": "IdenTrust",
    "type": "root",
    "status": "active",
    "crtsh": "https://crt.sh/?id=8395",
    "txt": "https://letsencrypt.org/certs/trustid-x3-root.txt",
    "pem": "https://letsencrypt.org/certs/trustid-x3-root.pem",
    "der": "https://letsencrypt.org/certs/trustid-x3-root.der",
    "signed_by": "https://letsencrypt.org/certs/trustid-x3-root.pem",  # self-signed
    },
    {
    "_name": "ISRG Root X1",
    "type": "root",
    "status": "active",
    "crtsh": "https://crt.sh/?id=9314791",
    "txt": "https://letsencrypt.org/certs/isrgrootx1.txt",
    "pem": "https://letsencrypt.org/certs/isrgrootx1.pem",
    "der": "https://letsencrypt.org/certs/isrgrootx1.der",
    "signed_by": "https://letsencrypt.org/certs/isrgrootx1.pem",  # self-signed
    },
    {
    "_name": "ISRG Root X2",
    "type": "root",
    "status": "upcoming",
    "crtsh": "https://crt.sh/?id=3335562555",
    "txt": "https://letsencrypt.org/certs/isrg-root-x2.txt",
    "pem": "https://letsencrypt.org/certs/isrg-root-x2.pem",
    "der": "https://letsencrypt.org/certs/isrg-root-x2.der",
    "signed_by": "https://letsencrypt.org/certs/isrg-root-x2.pem",  # self-signed
    },
    {
    "_name": "ISRG Root X2 - CROSS SIGNED",
    "type": "root",
    "status": "upcoming",
    "crtsh": "https://crt.sh/?id=3334561878",
    "txt": "https://letsencrypt.org/certs/isrg-root-x2-cross-signed.txt",
    "pem": "https://letsencrypt.org/certs/isrg-root-x2-cross-signed.pem",
    "der": "https://letsencrypt.org/certs/isrg-root-x2-cross-signed.der",
    "signed_by": "https://letsencrypt.org/certs/isrgrootx1.pem",
    "cross_signed_variant_of": "https://letsencrypt.org/certs/isrg-root-x2.pem",
    },
    {
    "_name": "Let's Encrypt R3",
    "type": "intermediate",
    "status": "active",
    "crtsh": "https://crt.sh/?id=3334561879",
    "txt": "https://letsencrypt.org/certs/lets-encrypt-r3.txt",
    "pem": "https://letsencrypt.org/certs/lets-encrypt-r3.pem",
    "der": "https://letsencrypt.org/certs/lets-encrypt-r3.der",
    "signed_by": "https://letsencrypt.org/certs/isrgrootx1.pem",
    },
    {
    "_name": "Let's Encrypt R3 -- CROSS",
    "type": "intermediate",
    "status": "active",
    "crtsh": "https://crt.sh/?id=3479778542",
    "txt": "https://letsencrypt.org/certs/lets-encrypt-r3-cross-signed.txt",
    "pem": "https://letsencrypt.org/certs/lets-encrypt-r3-cross-signed.pem",
    "der": "https://letsencrypt.org/certs/lets-encrypt-r3-cross-signed.der",
    "signed_by": "https://letsencrypt.org/certs/trustid-x3-root.pem",
    "cross_signed_variant_of": "https://letsencrypt.org/certs/lets-encrypt-r3.pem",
    },
    {
    "_name": "Let's Encrypt E1",
    "type": "intermediate",
    "status": "upcoming",
    "crtsh": "https://crt.sh/?id=3334671964",
    "txt": "https://letsencrypt.org/certs/lets-encrypt-e1.txt",
    "pem": "https://letsencrypt.org/certs/lets-encrypt-e1.pem",
    "der": "https://letsencrypt.org/certs/lets-encrypt-e1.der",
    "signed_by": "https://letsencrypt.org/certs/isrg-root-x2.pem",
    },
    {
    "_name": "Let's Encrypt R4",
    "type": "intermediate",
    "status": "backup",
    "crtsh": "https://crt.sh/?id=3334561877",
    "txt": "https://letsencrypt.org/certs/lets-encrypt-r4.txt",
    "pem": "https://letsencrypt.org/certs/lets-encrypt-r4.pem",
    "der": "https://letsencrypt.org/certs/lets-encrypt-r4.der",
    "signed_by": "https://letsencrypt.org/certs/isrgrootx1.pem",
    },
    {
    "_name": "Let's Encrypt R4 -- CROSS",
    "type": "intermediate",
    "status": "backup",
    "crtsh": "https://crt.sh/?id=3479778543",
    "txt": "https://letsencrypt.org/certs/lets-encrypt-r4-cross-signed.txt",
    "pem": "https://letsencrypt.org/certs/lets-encrypt-r4-cross-signed.pem",
    "der": "https://letsencrypt.org/certs/lets-encrypt-r4-cross-signed.der",
    "signed_by": "https://letsencrypt.org/certs/trustid-x3-root.pem",
    "cross_signed_variant_of": "https://letsencrypt.org/certs/lets-encrypt-r4.pem",
    },
    {
    "_name": "Let's Encrypt E2",
    "type": "intermediate",
    "status": "backup",
    "crtsh": "https://crt.sh/?id=3334671963",
    "txt": "https://letsencrypt.org/certs/lets-encrypt-e2.txt",
    "pem": "https://letsencrypt.org/certs/lets-encrypt-e2.pem",
    "der": "https://letsencrypt.org/certs/lets-encrypt-e2.der",
    "signed_by": "https://letsencrypt.org/certs/isrg-root-x2.pem",
    },
    {
    "_name": "Let's Encrypt Authority X1",
    "type": "intermediate",
    "status": "retired",
    "crtsh": "https://crt.sh/?id=9314792",
    "txt": "https://letsencrypt.org/certs/letsencryptauthorityx1.txt",
    "pem": "https://letsencrypt.org/certs/letsencryptauthorityx1.pem",
    "der": "https://letsencrypt.org/certs/letsencryptauthorityx1.der",
    "signed_by": "https://letsencrypt.org/certs/isrgrootx1.pem",
    },
    {
    "_name": "Let's Encrypt Authority X1 -- CROSS",
    "type": "intermediate",
    "status": "retired",
    "crtsh": "https://crt.sh/?id=10235198",
    "txt": "https://letsencrypt.org/certs/lets-encrypt-x1-cross-signed.txt",
    "pem": "https://letsencrypt.org/certs/lets-encrypt-x1-cross-signed.pem",
    "der": "https://letsencrypt.org/certs/lets-encrypt-x1-cross-signed.der",
    "signed_by": "https://letsencrypt.org/certs/trustid-x3-root.pem",
    },
    {
    "_name": "Let's Encrypt Authority X2",
    "type": "intermediate",
    "status": "retired",
    "crtsh": "https://crt.sh/?id=12721505",
    "txt": "https://letsencrypt.org/certs/letsencryptauthorityx2.txt",
    "pem": "https://letsencrypt.org/certs/letsencryptauthorityx2.pem",
    "der": "https://letsencrypt.org/certs/letsencryptauthorityx2.der",
    "signed_by": "https://letsencrypt.org/certs/isrgrootx1.pem",
    },
    {
    "_name": "Let's Encrypt Authority X2 -- CROSS",
    "type": "intermediate",
    "status": "retired",
    "crtsh": "https://crt.sh/?id=10970235",
    "txt": "https://letsencrypt.org/certs/lets-encrypt-x2-cross-signed.txt",
    "pem": "https://letsencrypt.org/certs/lets-encrypt-x2-cross-signed.pem",
    "der": "https://letsencrypt.org/certs/lets-encrypt-x2-cross-signed.der",
    "signed_by": "https://letsencrypt.org/certs/trustid-x3-root.pem",
    },
    {
    "_name": "Let's Encrypt Authority X3",
    "type": "intermediate",
    "status": "retired",
    "crtsh": "https://crt.sh/?id=47997543",
    "txt": "https://letsencrypt.org/certs/letsencryptauthorityx3.txt",
    "pem": "https://letsencrypt.org/certs/letsencryptauthorityx3.pem",
    "der": "https://letsencrypt.org/certs/letsencryptauthorityx3.der",
    "signed_by": "https://letsencrypt.org/certs/isrgrootx1.pem",
    },
    {
    "_name": "Let's Encrypt Authority X3 -- CROSS",
    "type": "intermediate",
    "status": "retired",
    "crtsh": "https://crt.sh/?id=15706126",
    "txt": "https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.txt",
    "pem": "https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem",
    "der": "https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.der",
    "signed_by": "https://letsencrypt.org/certs/trustid-x3-root.pem",
    },
    {
    "_name": "Let's Encrypt Authority X4",
    "type": "intermediate",
    "status": "retired",
    "crtsh": "https://crt.sh/?id=47997546",
    "txt": "https://letsencrypt.org/certs/letsencryptauthorityx4.txt",
    "pem": "https://letsencrypt.org/certs/letsencryptauthorityx4.pem",
    "der": "https://letsencrypt.org/certs/letsencryptauthorityx4.der",
    "signed_by": "https://letsencrypt.org/certs/isrgrootx1.pem",
    },
    {
    "_name": "Let's Encrypt Authority X4 -- CROSS",
    "type": "intermediate",
    "status": "retired",
    "crtsh": "https://crt.sh/?id=15710291",
    "txt": "https://letsencrypt.org/certs/lets-encrypt-x4-cross-signed.txt",
    "pem": "https://letsencrypt.org/certs/lets-encrypt-x4-cross-signed.pem",
    "der": "https://letsencrypt.org/certs/lets-encrypt-x4-cross-signed.der",
    "signed_by": "https://letsencrypt.org/certs/trustid-x3-root.pem",
    },
]



certs_formatted = []

for cert_payload in cert_sources:
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
            "selfsigned": True if cert_payload["signed_by"] == cert_payload['pem'] else False,
        },
        "issuer": {
            "o": issuer["O"],
            "cn": issuer["CN"],
            "url_pem": cert_payload["signed_by"],
        }
    }
    certs_formatted.append(cert_data)




#pprint.pprint(certs_formatted)
# print("------")
_today = datetime.datetime.today()
certs_json = {
    "lastmod": _today.strftime("%Y-%0m-%0d"),
    "certificates": certs_formatted,
}

with open("certificates.json", "w") as fp:
    fp.write(json.dumps(certs_json, sort_keys=True, indent=2))






