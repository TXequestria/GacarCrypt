# -*- coding: utf-8 -*-

#import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from hashlib import sha256
import os
from shutil import rmtree

def AES_mult_encrypt(data_list,directory,finalFile):
    #data list 是一个多维数组，每一行都是
    #[要加密的文件的文件名，密码（用户输入的密码，string类型），
    #密钥（16，24或32字节长的bytes，用get_random_bytes（）生成]的格式
    #directory是工作路径，要求以“\”结尾
    #finalFile是文件名，就是加密后的文件的名字
    
    def header_gen(data,enc,start):
        #data是[文件名,密码,密钥]列表，
        #start是文件开始写入的地方，如对第一个文件，就是文件头结束的位置
        header_start = b'\xe47\x0e\xeb\xefq\xc0\xa9'
        header_end   = b'\xa5\x84\x8cB\xbf\xef\x1c\xd7'
        #用于标志一个256字节的文件头的头尾
        #文件头：8字节标志位+32字节加密校验码+32字节密钥+2*88字节文件指针+8字节文件头标志位
        file_size = os.path.getsize(enc)
        end = start + file_size 
        if len(str(end).encode()) > 88 or end < 0 or start < 0:
            raise ValueError ("File too big!")
        
        key_bit = data[2] + bytes(32-len(data[2]))#密钥，32字节
        start_bit = str(start).encode() + bytes(88 -len(str(start).encode()))#文件指针起始数值，88字节
        end_bit = str(end).encode() + bytes(88-len(str(end).encode()))#文件指针结束数值，88字节
        bit = key_bit + start_bit + end_bit 
        del key_bit, start_bit, end_bit
        nonce, tag, ciphertext = AES_encrypt(bit,sha256((data[1]).encode()).digest())
        del bit
        bit = header_start + nonce + tag + ciphertext + header_end
        return [bit,end]
    if not directory[-1] in ["\\","/"] :
        directory = directory + "\\"
    temp_dir = directory + "temp" + '\\'
    if not(os.path.isdir(temp_dir)):
        os.mkdir(temp_dir) 
    start = len(data_list)*256
    temp_header = temp_dir + "temp_head"
    temp_encrypt = []
    for x in range(len(data_list)):
        temp_encrypt.append(temp_dir + "tmp_enc" + str(x))
    del x
    for x in range(len(data_list)):
        AES_encrypt_file(data_list[x][0],temp_encrypt[x],data_list[x][2])
    del x
    
    
    with open(temp_header,'wb') as f:
        for x in range(len(data_list)):
            bit,start = header_gen(data_list[x],temp_encrypt[x],start)
            f.write(bit)
        del x
        f.close()
    
    with open(finalFile,'wb') as f_final:
        with open(temp_header,'rb') as f:
            a = bytes(1)
            while(len(a)>0):
                a = f.read(1)
                if len(a) == 1:
                    f_final.write(a)
            f.close()
        for x in temp_encrypt:
            with open(x,'rb') as f:
                a = bytes(1)
                while(len(a)>0):
                    a = f.read(1)
                    if len(a) == 1:
                        f_final.write(a)
                f.close()
        f_final.close()
    rmtree(temp_dir)
    return None

def AES_mult_decrypt(password,source,des):
    #password 是用户输入的密码，string类型
    #source 是加密好的源文件
    #des 是目标地址文件夹,以”\"结尾，用于存放解密后的文件
    header_start = b'\xe47\x0e\xeb\xefq\xc0\xa9'
    header_end   = b'\xa5\x84\x8cB\xbf\xef\x1c\xd7'
    with open(source,'rb') as f_s:#打开文件，记得删除
        header_list = []
        h = f_s.read(256)
        while h[0:8] == header_start and h[248:256] == header_end:
            header_list.append(h[8:248])
            h = f_s.read(256)
        del h
        if header_list == []:
            f_s.close()
            raise TypeError ("Not a mult-encrypt file")
            return None
        data = []
        for x in header_list:
            try:
                key = sha256(password.encode()).digest()
                ciphertext = AES_decrypt([x[0:16],x[16:32],x[32:]],key)
                key_bit = ciphertext[0:32]
                start_bit = ciphertext[32:120]
                end_bit = ciphertext[120:]
                del key,ciphertext
                for i in range(32):
                    if key_bit[i:]==bytes(32-i):
                        key_bit = key_bit[0:i]
                        break
                for i in range(88):
                    if start_bit[i:] == bytes(88-i):
                        start_bit = start_bit[0:i]
                        break
                for i in range(88):
                    if end_bit[i:] == bytes(88-i):
                        end_bit = end_bit[0:i]
                        break
                del i
                start = int(start_bit.decode())
                end   = int(end_bit.decode())
                del start_bit,end_bit
                data.append([key_bit,start,end])
                del key_bit,start,end
            except ValueError:
                continue
        del x,header_list
        if data == [] or data[0] == [] :
            f_s.close()
            raise ValueError ("Password incorrect")
            return None
        temp_dir = des+"temp\\"
        if not(os.path.isdir(des)):
            os.mkdir(des)
        if not(os.path.isdir(temp_dir)):
            os.mkdir(temp_dir)
        temp_file = []
        for i in range(len(data)):
            temp_file.append(temp_dir+"enc"+str(i))
            with open(temp_file[i],'wb') as f_temp:
                f_s.seek(data[i][1],0)
                while f_s.tell() < data[i][2]:
                    f_temp.write(f_s.read(1))
                f_temp.close()
            for i in range(len(data)):
                AES_decrypt_file(temp_file[i],des,data[i][0])
        f_s.close()
    rmtree(temp_dir)
    return None


#输入bitstring输出列表
def AES_encrypt(data,key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return [cipher.nonce, tag, ciphertext]
#输入列表输出bitstring
def AES_decrypt(data_list,key):
    nonce,tag,ciphertext = data_list
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data

#输入文本输出列表
def AES_encrypt_text(data,key):
    key = sha256(key.encode()).digest()
    data_b = data.encode("utf-8")
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data_b)
    return (cipher.nonce+ tag+ciphertext).hex()

#输入文本文件输出文本
def AES_decrypt_text(hexstring,key):
    key = sha256(key.encode()).digest()
    bits = bytes.fromhex(hexstring)
    nonce = bits[0:16]
    tag = bits[16:32]
    ciphertext = bits[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data.decode("utf-8")

def AES_encrypt_file(original_file,encrypted_file,key):
    file_name = os.path.basename(original_file)
    f_bit = file_name.encode()
    f_bit = f_bit + bytes(64-len(f_bit))
    del file_name
    nonce,tag,ciphertext = AES_encrypt(f_bit,key)
    del f_bit
    with open(original_file,'rb') as o, open(encrypted_file,'wb') as e:
        try:
            for x in [nonce,tag,ciphertext]:
                e.write(x)
            f_bit = bytes(1024)
            while len(f_bit) == 1024:
                f_bit = o.read(1024)
                if len(f_bit) > 0:
                    nonce,tag,ciphertext = AES_encrypt(f_bit,key)
                    for x in [nonce,tag,ciphertext]:
                        e.write(x)
        finally:
            e.close()
            o.close()
    return None
    
def AES_decrypt_file(encrypted_file,des_dir,key):
    with open(encrypted_file,'rb') as fe:
        data = [fe.read(x) for x in [16,16,64]]
        file_name = AES_decrypt(data,key)
        for i in range(len(file_name)):
            if file_name[i:] == bytes(len(file_name)-i):
                file_name = file_name[0:i]
                break
        file_name = des_dir + file_name.decode() 
        with open(file_name,'wb') as fd:
            try:
                data = [bytes(16),bytes(16),bytes(1024)]
                while len(data[2]) == 1024:
                    data = [fe.read(x) for x in [16,16,1024]]
                    if len(data[2]) > 0:
                        fd.write(AES_decrypt(data,key))
            finally:
                fe.close()
                fd.close()
    return None
