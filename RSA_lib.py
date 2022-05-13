# -*- coding: utf-8 -*-
"""
Created on Wed Apr  6 19:25:08 2022

@author: User
"""


from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import os


def RSA_key_gen(file,passphrase = None,keysize=4096):
    random_generator = Random.new().read
    key = RSA.generate(keysize, random_generator)
    pub = file + ".pub"
    pri = file + ".pri"
    with open(pub,'wb') as f, open(pri,'wb') as f2:
        f2.write(key.export_key('PEM',passphrase))
        f.write(key.publickey().exportKey('PEM'))
        f2.close()
        f.close()
    return [key,key.public_key()]

def RSA_key_read(file,passphrase=None):
    with open(file,'r') as f:
        key = RSA.import_key(f.read(),passphrase)
    return key

def RSA_encrypt_bit(bit_to_encrypt,public_key):
    a,b,n = [0,0,0]
    block_len = public_key.size_in_bytes() - 66
    cipher = PKCS1_OAEP.new(public_key,SHA256)
    if len(bit_to_encrypt) <= block_len:
        ciphertext = cipher.encrypt(bit_to_encrypt)
    else:
        n = int(len(bit_to_encrypt)/block_len)
        ciphertext = bytes(0)
        for i in range(n):
            a = i*block_len
            b = a+block_len
            ciphertext = ciphertext + cipher.encrypt(bit_to_encrypt[a:b])
        ciphertext = ciphertext + cipher.encrypt(bit_to_encrypt[b:])
    return ciphertext

def RSA_decrypt_bit(bits,key):
    a = 0
    b = 0
    n = len(bits)/(key.size_in_bytes())
    n = int(n)
    cipher = PKCS1_OAEP.new(key,SHA256)
    plainbit = bytes(0)
    for i in range(n):
        a = i*key.size_in_bytes()
        b = a + key.size_in_bytes()
        plainbit = plainbit + cipher.decrypt(bits[a:b])
    return plainbit


def RSA_encrypt_file(file,new_file,pubkey):
    block_len = pubkey.size_in_bytes() - 66
    name = os.path.basename(file)
    name = name.encode()
    bit_out = RSA_encrypt_bit(name,pubkey)
    bit_in = bytes(block_len)
    with open(file,'rb') as o, open(new_file,'wb') as e:
        e.write(bit_out)
        while len(bit_in) == block_len:
            bit_in = o.read(block_len)
            if len(bit_in) > 0:
                bit_out = RSA_encrypt_bit(bit_in,pubkey)
                e.write(bit_out)
        e.close()
        o.close()
    return 0

def RSA_decrypt_file(file,directory,key):
    if not(os.path.isdir(directory)):
        os.mkdir(directory)
    block = key.size_in_bytes()
    with open(file,'rb') as e:
        bit_in = e.read(block)
        name = RSA_decrypt_bit(bit_in,key)
        name = name.decode()
        file_out = directory + name
        with open(file_out,'wb') as o:
            while len(bit_in) == block:
                bit_in = e.read(block)
                if len(bit_in) > 0:
                    bit_out = RSA_decrypt_bit(bit_in, key)
                    o.write(bit_out)
            o.close()
        e.close()
    return 0

def RSA_sign_bit(bit,key):
    signer = PKCS1_v1_5.new(key)
    hasher = SHA256.new()
    hasher.update(bit)
    sig = signer.sign(hasher)
    return sig.hex()


def RSA_verify_bit(bit,sig,pubkey):
    hasher = SHA256.new()
    hasher.update(bit)
    s = bytes.fromhex(sig)
    verifier = PKCS1_v1_5.new(pubkey)
    r = verifier.verify(hasher, s)
    return r

def RSA_sign_file(file,key,sf = None):
    def File_HASH(file):
        with open(file,'rb') as f:
            a = f.read(1)
            h = SHA256.new()
            while len(a) > 0:
                h.update(a)
                a = f.read(1)
        return h
    h = File_HASH(file)
    signer = PKCS1_v1_5.new(key)
    signature = signer.sign(h)
    if sf == None:
        return signature.hex()
    else:
        with open(sf,'w') as f:
            f.write(signature.hex())
            f.close()
            return signature.hex()

def RSA_verify_file(file,pubkey,signature = None, sf = None):
    def File_HASH(file):
        with open(file,'rb') as f:
            a = f.read(1)
            h = SHA256.new()
            while len(a) > 0:
                h.update(a)
                a = f.read(1)
        return h
    verifier = PKCS1_v1_5.new(pubkey)
    if (signature == None and sf == None) :
        raise AttributeError ("Must input a file or signature") 
        return 0
    elif not(signature == None) and not(sf == None):
        raise AttributeError ("Must input one of file or signature")
        return 0
    elif not(signature == None):
        s = bytes.fromhex(signature)
        h = File_HASH(file)
        result = verifier.verify(h, s)
        return result
    else:
        with open(sf,'r') as f:
            s = f.read()
            f.close()
        s = bytes.fromhex(s)
        h = File_HASH(file)
        result = verifier.verify(h, s)
        return result

