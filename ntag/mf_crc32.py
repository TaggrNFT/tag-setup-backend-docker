"""
MIFARE DESFire EV1 protocol implementation

This implementation is based on the following publicly available sources:
* Mifare Desfire communication example
  https://ridrix.wordpress.com/2009/09/19/mifare-desfire-communication-example/
* Desfire EV1 Communication Examples from sotechcllc/RFDoorLock
  https://github.com/sotechcllc/RFDoorLock/blob/b57097cf6e524c05f5b0ae957d84b6ca40a1dbfe/Desfire%20EV1%20Communication%20Examples.htm
* nceruchalu/easypay GitHub Project
  https://github.com/nceruchalu/easypay/blob/e22fcc786429cd0ce95c202b188dd8c03f25bd9c/mifare/mifare_crypto.c
* nfc-tools/libfreefare GitHub Project
  https://github.com/nfc-tools/libfreefare/blob/682fbe69bd9ce1de389526b1b5f24de2af861e4d/libfreefare/mifare_desfire.c
* Stack Overflow question about CRC32 implementation
  https://stackoverflow.com/questions/41564890/crc32-calculation-in-python-without-using-libraries
* Inspired by public Application Note 12113 "Over-the-Air top-up with MIFARE DESFire EV2 and MIFARE Plus EV1"
  https://www.nxp.com/docs/en/application-note/AN12113.pdf
"""

from array import array

poly = 0xEDB88320

table = array('L')
for byte in range(256):
    crc = 0
    for bit in range(8):
        if (byte ^ crc) & 1:
            crc = (crc >> 1) ^ poly
        else:
            crc >>= 1
        byte >>= 1
    table.append(crc)


def mf_crc32(string):
    value = 0xffffffff
    for ch in string:
        value = table[(ch ^ value) & 0xff] ^ (value >> 8)

    return value
