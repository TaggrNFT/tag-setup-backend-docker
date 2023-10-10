import binascii


ADMIN_AUTH_CODE = "testing"

# please don't modify the part after '?' sign
# this is required for proper operation
URL = 'http://10.0.0.44:5000/demo' \
      '?enc=' \
      '@@@HASH@@@@@@@@@@@@@@@@@@@@@@@@@' \
      '@@@PICCDATA@@@@@@@@@@@@@@@@@@@@@' \
      '@@@ENCFILEDATA@@@@@@@@@@@@@@@@@@' \
      '@@@CMAC@@@@@@@@@'

UPDATE_URL = 'http://127.0.0.1/api/newtag/'

MASTER_KEY = [
    binascii.unhexlify("d4787e885637c02c1333518846b2629e"),
    binascii.unhexlify("7a5037005d55e31ed9c99c45a2614f48"),
    binascii.unhexlify("1c2ae7f57341a520a7d4bbf5be7a805b"),
    binascii.unhexlify("4fdf0fc1e1125de5b98701cf7ce98aef"),
    binascii.unhexlify("a1928a184d4e7393628af81803d1beac")
]

PBKDF_ROUNDS = 1000

TAG_HASH_KEY = binascii.unhexlify("b57bcd4a8a8499624858f2dc5b19ef02")
TAG_SECRET_KEY = binascii.unhexlify("c952c99d41713968dee6ca1c2a63a412")
