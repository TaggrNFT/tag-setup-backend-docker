import os
import binascii


SDMMAC_PARAM = ""

# please don't modify the part after '?' sign
# this is required for proper operation
URL = os.environ['NFC_URL'] + \
      '?enc=' \
      '@@@HASH@@@@@@@@@@@@@@@@@@@@@@@@@' \
      '@@@PICCDATA@@@@@@@@@@@@@@@@@@@@@' \
      '@@@ENCFILEDATA@@@@@@@@@@@@@@@@@@' \
      '@@@CMAC@@@@@@@@@'

UPDATE_URL = os.environ['UPDATE_URL']

ADMIN_AUTH_CODE = os.environ['NFC_ADMIN_AUTH_CODE']

MASTER_KEY = [
    binascii.unhexlify(os.environ['NFC_MASTER_KEY_0']),
    binascii.unhexlify(os.environ['NFC_MASTER_KEY_1']),
    binascii.unhexlify(os.environ['NFC_MASTER_KEY_2']),
    binascii.unhexlify(os.environ['NFC_MASTER_KEY_3']),
    binascii.unhexlify(os.environ['NFC_MASTER_KEY_4'])
]

PBKDF_ROUNDS = int(os.environ['NFC_PBKDF_ROUNDS'])

TAG_HASH_KEY = binascii.unhexlify(os.environ['NFC_TAG_HASH_KEY'])
TAG_SECRET_KEY = binascii.unhexlify(os.environ['NFC_TAG_SECRET_KEY'])
