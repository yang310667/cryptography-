from Crypto.PublicKey import ECC

key = ECC.generate(curve='P-256')

publickey = key.public_key()

pk = str(publickey)

with open('private_key','wt') as f:
    f.write(key.export_key(format='PEM'))
    f.close()
with open('public_key','w') as f:
    f.write(pk)
    f.close

