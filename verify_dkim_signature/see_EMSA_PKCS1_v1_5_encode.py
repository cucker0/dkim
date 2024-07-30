from dkim.asn1 import asn1_build, SEQUENCE, OBJECT_IDENTIFIER, OCTET_STRING, NULL
from dkim.crypto import HASH_ID_MAP, DigestTooLargeError


def EMSA_PKCS1_v1_5_encode(hash, mlen):
    """Encode a digest with RFC8017 EMSA-PKCS1-v1_5.

    @param hash: hash object to encode
    @param mlen: desired message length
    @return: encoded digest byte string
    """
    dinfo = asn1_build(
        (SEQUENCE, [
            (SEQUENCE, [
                (OBJECT_IDENTIFIER, HASH_ID_MAP[hash.name.lower()]),
                (NULL, None),
            ]),
            (OCTET_STRING, hash.digest()),
        ]))
    if len(dinfo) + 11 > mlen:
        raise DigestTooLargeError()
    return b"\x00\x01"+b"\xff"*(mlen-len(dinfo)-3)+b"\x00"+dinfo