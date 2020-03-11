#!/usr/bin/env python

from ledgerblue.comm import getDongle
from binascii import unhexlify

apduMessage = "E00300000401000000"
apdu = bytearray.fromhex(apduMessage)

print("Request Address")

dongle = getDongle(True)
generatedKey = dongle.exchange(apdu)
