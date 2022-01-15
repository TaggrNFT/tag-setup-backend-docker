import binascii
import struct

import ndef


def create_ndef(url, tag_hash, tag_secret, with_tt):
    orig_prefix = ndef.UriRecord._prefix_strings
    ndef.UriRecord._prefix_strings = [""]

    # NDEF encoding type #1, alternative
    records = [
        ndef.UriRecord(url),
    ]

    payload = b''.join((ndef.message_encoder(records)))
    encoded_ndef = b'\x00' + bytes([len(payload)]) + payload
    ndef.UriRecord._prefix_strings = orig_prefix

    marker_tag_hash = b'@@@HASH@@@@@@@@@@@@@@@@@@@@@@@@@'
    marker_picc_data = b'@@@PICCDATA@@@@@@@@@@@@@@@@@@@@@'
    marker_cmac = b'@@@CMAC@@@@@@@@@'
    marker_enc = b'@@@ENCFILEDATA@@@@@@@@@@@@@@@@@@'

    a = encoded_ndef.find(marker_picc_data)
    b = encoded_ndef.find(marker_cmac)
    c = encoded_ndef.find(marker_enc)
    d = encoded_ndef.find(marker_tag_hash)

    if a < 0 or b < 0 or c < 0 or d < 0:
        raise RuntimeError("Missing URL markers")

    if len(tag_hash) != len(marker_tag_hash):
        raise RuntimeError("Invalid length of tag hash")

    if len(tag_secret) != 12:
        raise RuntimeError("Invalid length of tag secret")

    if with_tt:
        sdm_options = binascii.unhexlify("d9")
        tt_status_offset = struct.pack("<I", c + 2)[0:3]
        enc_payload = b"TT" + b"XX" + tag_secret.encode('ascii') + (b"X" * 16)
    else:
        sdm_options = binascii.unhexlify("d1")
        tt_status_offset = b""
        enc_payload = b"NT" + b"XX" + tag_secret.encode('ascii') + (b"X" * 16)

    encoded_ndef = encoded_ndef.replace(marker_tag_hash, tag_hash)
    encoded_ndef = encoded_ndef.replace(marker_picc_data, b"0" * len(marker_picc_data))
    encoded_ndef = encoded_ndef.replace(marker_cmac, b"0" * len(marker_cmac))
    encoded_ndef = encoded_ndef.replace(marker_enc, enc_payload)

    file_2_access = (
        binascii.unhexlify("43") +    # [File Option - 1]
        binascii.unhexlify("0000") +  # [Access Rights - 2]
        sdm_options +                 # [SDM Options - 1]
        binascii.unhexlify("ff12") +  # [SDMAccessRights - 2]
        struct.pack("<I", a)[0:3] +   # [PICCDataOffset - 3]
        tt_status_offset +            # [TTStatusOffset - 3]
        struct.pack("<I", c)[0:3] +   # [SDMMACInputOffset - 3]
        struct.pack("<I", c)[0:3] +   # [SDMENCOffset - 3]
        struct.pack("<I", 32)[0:3] +  # [SDMENCLength - 3]
        struct.pack("<I", b)[0:3])    # [SDMMACOffset - 3]

    return encoded_ndef, file_2_access
