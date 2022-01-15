# Verify asymmetric originality signature
# Based on public AN12196 8.2 Asymmetric check

import sys
import binascii

from ecdsa import VerifyingKey
from ecdsa.curves import SECP128r1, NIST224p
from ecdsa.keys import BadSignatureError

PUBLIC_KEY_NTAG424 = binascii.unhexlify(b"048A9B380AF2EE1B98DC417FECC263F8449C7625CECE82D9B916C992DA209D68422B81EC20B65A66B5102A61596AF3379200599316A00A1410")
PUBLIC_KEY_NTAG5 = binascii.unhexlify(b"04494E1A386D3D3CFE3DC10E5DE68A499B1C202DB5B132393E89ED19FE5BE8BC61")


def validate_ntag424(uid: bytes, sig: bytes) -> bool:
    vk = VerifyingKey.from_string(PUBLIC_KEY_NTAG424, curve=NIST224p)
    
    try:
        vk.verify_digest(sig, uid)
    except BadSignatureError:
        return False
    
    return True


def validate_ntag5(uid: bytes, sig: bytes) -> bool:
    vk = VerifyingKey.from_string(PUBLIC_KEY_NTAG5, curve=SECP128r1)
    
    try:
        vk.verify_digest(sig, uid)
    except BadSignatureError:
        return False
    
    return True


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print('Usage: python3 validate_ecc.py ntag424|ntag5 <uid> <sig>')
        print('    uid - tag UID, hex encoded')
        print('    sig - originality signature as returned by Read_Sig')
        print('Example:')
        print('    python3 validate_ecc.py ntag424 04518DFAA96180 D1940D17CFEDA4BFF80359AB975F9F6514313E8F90C1D3CAAF5941AD744A1CDF9A83F883CAFE0FE95D1939B1B7E47113993324473B785D21')
        print('    python3 validate_ecc.py ntag5 00107646580104E0 0AAB09CC328B20A133790D386C07890D623C027FD59A98F0115987BDE70503CD')
        sys.exit(2)

    tag_type = sys.argv[1]
    uid = binascii.unhexlify(sys.argv[2])
    sig = binascii.unhexlify(sys.argv[3])

    if tag_type == 'ntag424':
        fun = validate_ntag424
    elif tag_type == 'ntag5':
        fun = validate_ntag5
    else:
        raise RuntimeError('Invalid tag type.')

    if fun(uid, sig):
        print('OK')
        sys.exit(0)
    else:
        print('INVALID')
        sys.exit(1)

