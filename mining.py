import hashlib, struct
import codecs

ver = 0x20400000
prev_block = "00000000000000000006a4a234288a44e715275f1775b77b2fddb6c02eb6b72f"
mrkl_root = "2dc60c563da5368e0668b81bc4d8dd369639a1134f68e425a9a74e428801e5b8"
time_ = 0x5DB8AB5E
bits = 0x17148EDF

exp = bits >> 24
mant = bits & 0xffffff
target_hexstr = '%064x' % (mant * (1<<(8*(exp - 3))))
target_str = codecs.decode(target_hexstr, 'hex')

print('First 5 values:')

nonce = 3000000000              #3100000000 pentru cazul 2
while nonce < 3100000000:       #3200000100 pentru cazul 2
    header = ( struct.pack("<L", ver) + codecs.decode(prev_block, 'hex')[::-1] + codecs.decode(mrkl_root, 'hex')[::-1] + struct.pack("<LLL", time_, bits, nonce))
    hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    if hash[::-1] < target_str:
        print('success')
        print('Nonce: ')
        print(nonce)
        print('Valoare hash: ')
        print(codecs.encode(hash[::-1], 'hex'))
        break
    if nonce < 3000000005:      #3200000005 pentru cazul 2
        print('Nonce: ')
        print(nonce)
        print('Valoare hash: ')
        print(codecs.encode(hash[::-1], 'hex'))
    nonce += 1


