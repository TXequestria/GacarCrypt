# -*- coding: utf-8 -*-

from AES_lib import *
from RSA_lib import *
from stegano import lsb
def hybrid_encrypt_file(file, desfile, pubkey):
    if pubkey.size_in_bytes() <=256:
        aeskey = get_random_bytes(16)
    elif pubkey.size_in_bytes() <=384:
        aeskey = get_random_bytes(24)
    else:
        aeskey = get_random_bytes(32)
    head = RSA_encrypt_bit(aeskey, pubkey)
    tempfile = desfile+".temp"
    try:
        AES_encrypt_file(file,tempfile,aeskey)
        with open(desfile,'wb') as f,open(tempfile,'rb') as f2:
            f.write(head)
            a = f2.read(1)
            while len(a) > 0:
                f.write(a)
                a = f2.read(1)
            f.close()
            f2.close()
    finally:
        if os.path.exists(tempfile):
            os.remove(tempfile)
    return 0

def hybrid_decrypt_file(file,desdir,key):
    if not(os.path.isdir(desdir)):
        os.mkdir(desdir)
    if desdir[-1] != "\\" or desdir[-1] != "/":
        desdir = desdir + "\\"
    tempfile = desdir + "temp.temp"
    with open(file,'rb') as f:
        aeskey = f.read(key.size_in_bytes())
        f.close()
    aeskey = RSA_decrypt_bit(aeskey, key)
    with open(file,'rb') as f,open(tempfile,'wb') as f1:
        a = f.read(key.size_in_bytes())
        a = f.read(1)
        while len(a) > 0:
            f1.write(a)
            a=f.read(1)
        f.close()
        f1.close()
    try:
        AES_decrypt_file(tempfile, desdir, aeskey)
    finally:
        os.remove(tempfile)
    return 0

def text_split_encrypt(file,des_dir,finalFile,mode="平级模式"):
#分界行的格式：任意空格+16个‘#’+空格+name=（不带路径的文件名）+空格+pass=（不带空格的密码）+空格+keylen=16，24，32+16个‘*’ 
    def is_split_line(line):
        wordlist = line.split()
        if len(wordlist) != 5:
            return False
        elif wordlist[0] != "################" or wordlist[-1] != "****************":
            return False
        elif wordlist[1][0:5] != "name=" or wordlist[2][0:5] != "pass=":
            return False
        elif  wordlist[3][0:7] !="keylen=" or  wordlist[3][7:] not in ["16","24","32"]:
            return False
        elif len(wordlist[1]) <= 5 or len(wordlist[2]) <=5 or len(wordlist[3]) <=7:
            return False
        else:
            return [True,wordlist[1][5:],wordlist[2][5:],int(wordlist[3][7:])]
    if file[len(file) - 4:len(file)] != ".txt":
        raise TypeError ("Not a text file!")
    else:
        with open(file,'r',encoding=('utf-8')) as f:
            line = f.readline()
            data = is_split_line(line)
            f.close()
        if not data:
            raise TypeError ("Not a Split-able file")
        else:
            temp_dir = des_dir + "temp\\"
            if not(os.path.exists(temp_dir)):
                os.mkdir(temp_dir)
            with open(file,'r',encoding=('utf-8')) as f:
                line = f.readline()
                data = is_split_line(line)
                seek_loc = []
                data_list = []
                while len(line) > 0:
                    if not(not(data)):
                        seek_loc.append(f.tell())
                        data_list.append([temp_dir+data[1],data[2],get_random_bytes(data[3])])
                    line = f.readline()
                    data = is_split_line(line)
                f.seek(0)
                if mode=="平级模式":
                    for i in range(len(seek_loc)):
                        f.seek(seek_loc[i])
                        with open(data_list[i][0],'w',encoding=('utf-8')) as f_out:
                            line = f.readline()
                            while (len(line) > 0) and not(is_split_line(line)):
                                f_out.write(line)
                                line = f.readline()
                            f_out.close()
                elif mode == "上下级模式":
                    for i in range(len(seek_loc)):
                        f.seek(seek_loc[i])
                        with open(data_list[i][0],'w',encoding=('utf-8')) as f_out:
                            line = f.readline()
                            while (len(line) > 0):
                                if not(is_split_line(line)):
                                    f_out.write(line)
                                line = f.readline()
                            f_out.close()
                f.close()
            try:
                AES_mult_encrypt(data_list,temp_dir,finalFile)
            finally:
                rmtree(temp_dir)
    return data_list

def lsb_hide_msg(ori_pic,des_pic,msg):
    msg = msg.encode()
    msg = msg.hex()
    if ori_pic[len(ori_pic)-4:] != ".png" or des_pic[len(des_pic)-4:] != ".png":
        raise TypeError("Not a png file!")
    elif os.path.getsize(ori_pic)/64 < len(msg):
        raise ValueError("Picture too small or text to long!")
    else:
        secret = lsb.hide(ori_pic,msg)
        secret.save(des_pic)
    return 0
def lsb_show_msg(img):
    if img[len(img)-4:]!=".png":
        raise TypeError("Not a png file!")
    a = lsb.reveal(img)
    if a is None:
        raise ValueError("No Message")
    else:
        try:
            b = bytes.fromhex(a)
        except:
            raise UnicodeError("message found but cannot decode")
        else:
            return b.decode()
    return None

