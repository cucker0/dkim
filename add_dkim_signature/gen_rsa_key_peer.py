"""
生成 RSA 私钥、公钥
"""

from Crypto import Random
from Crypto.PublicKey import RSA

# 伪随机数生成器
random_generator = Random.new().read

# RAS 算法生成器
rsa = RSA.generate(2048, random_generator)

# 生成私钥
private_key = rsa.exportKey()
with open('./private.pem', 'wb') as f:
    f.write(private_key)

# 生成公钥
public_key = rsa.publickey().exportKey()
with open('./public.pem', 'wb') as f:
    f.write(public_key)