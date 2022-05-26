# -*- coding: utf-8 -*-

from file_manipulate import *
from tkinter import *
from tkinter.ttk import *
from tkinter import messagebox
from tkinter import filedialog

def GUI_AES_file_encrypt(source_file,des_file,password,keylen):
    key = get_random_bytes(keylen)
    AES_encrypt_file(source_file,des_file,key)
    with open(des_file,'br+') as f:
        f.seek(0,2)
        key = key + bytes(32-keylen)
        for x in AES_encrypt(key,sha256(password.encode()).digest()):
            f.write(x)
    return 0

def GUI_AES_file_decrypt(encrypted_file,des_dir,password):
    password = sha256(password.encode()).digest()
    with open(encrypted_file,'br+')as f:
        f.seek(-(16+16+32),2)
        data = [f.read(x) for x in [16,16,32]]
        key = AES_decrypt(data,password)
        for i in range(32):
            if key[i:] == bytes(32-i):
                key = key[0:i]
        f.seek(-(16+16+32),2)
        f.truncate()
    AES_decrypt_file(encrypted_file, des_dir, key)
    with open(encrypted_file,'br+')as f:
        f.seek(0,2)
        for x in data:
            f.write(x)
    return 0

def AES_window():
    root = Tk()
    root.title('AES对称加密')
    des_file_1=StringVar()
    source_file=StringVar()
    working_dir = StringVar()
    #一些变量
    mode_list = ["普通文件加密","普通文件解密","普通文本加密",
                 "普通文本解密","多密码文本加密","多密码文本解密"]
    #变量结束
    
    #函数部分：
    def chbtntxt():
        des_file_1.set("")
        source_file.set("")
        long_input.delete(1.0,'end')
        key_len.delete(0,END)
        password.delete(0,END)
        working_dir.set("")
        m = mode.get()
        password.configure(state='enabled')
        if m in [4,5]:
            key_len_text.configure(text="输入文件分割模式,“平级模式”或“上下级模式”")
            if m == 4:
                password.configure(state='disabled')
            else:
                password.configure(state='enabled')
        else:
            key_len_text.configure(text="输入密钥长度")
        if m in [1,3,5]:
            en_de_btn.configure(text="解密")
            des_file_text.configure(text='输入加密后的目标文件完整路径:')
        else:
            des_file_text.configure(text='输入加密后的目标文件完整路径:')
            en_de_btn.configure(text="加密")
        #当不在文件加密操作时，禁用"目标文件输入框"、"密钥长度"
        if not m in [0,4]:
            des_file.configure(state ="disabled")
            key_len.configure(state ="disabled")
        else:
            key_len.configure(state ="normal")
            des_file.configure(state ="normal")
        #当不在文件解密的时候，禁用“目标路径”
        if not m in [1,5]:
            working_dir_1.configure(state ="disabled")
        else:
            working_dir_1.configure(state ="normal")
        #当不是文本操作时，禁用长文本输入框
        if not m in [3,2]:
            long_input.configure(state ="disabled")
        else:
            long_input.configure(state ="normal")
        return 0
    def browseFiles():
        source_file.set(filedialog.askopenfilename(initialdir = "/",
                                          title = "选择文件",
                                          filetypes = (("所有文件",
                                           "*.*"),
                                              ("文本文件",
                                                        "*.txt"),
                                                       ("Gacar普通加密文件",
                                                        "*.gac"),
                                                       ("Gacar多密码加密文件",
                                                        "*.gacm")
                                                       )))
    # Change label contents
        return 0
    def browseFiles_1():
        files = [('Gacar普通加密文件','*.gac'),
                 ('Gacar多密码加密文件','*.gacm'),('文本文件', '*.txt'),('所有文件', '*.*')]
        des_file_1.set(filedialog.asksaveasfilename(initialdir = "/",title = "保存为",
                                        filetypes = files, defaultextension = files))
        return 0
    def btnfunc():
        m=mode.get()
        if m == 0:
            try:
                GUI_AES_file_encrypt(source_file.get(),des_file_1.get(),password.get(),int(key_len.get()))
            except ValueError:
                messagebox.showerror("加密失败","密钥长度必须是16，24或32")
            except FileNotFoundError:
                messagebox.showerror("加密失败","请确认要加密的文件是否存在")
            except Exception as e:
                messagebox.showerror("加密失败","错误信息"+str(e))
            else:
                messagebox.showinfo("加密成功","加密成功")
        elif m == 1:
            try:
                dire = working_dir.get()
                if not os.path.exists(working_dir.get()):
                    os.mkdir(working_dir.get())
                if working_dir.get()[-1] != '\\':
                    dire = working_dir.get() + "\\"
                GUI_AES_file_decrypt(source_file.get(),dire,password.get())
            except ValueError:
                messagebox.showerror("解密失败","请检查密码或确认文件确实是一个AES常规加密文件")
            except FileNotFoundError:
                messagebox.showerror("解密失败","请确认要解密的文件是否存在")
            except Exception as e:
                messagebox.showerror("解密失败","错误信息"+str(e))
            else:
                messagebox.showinfo("解密成功","解密成功")
        elif m == 2:
            if len(long_input.get(1.0,'end')) > 1:
                print(len(long_input.get(1.0,'end')))
                cleartext = long_input.get(1.0,'end')
                enc_hex = AES_encrypt_text(cleartext,password.get())
                long_input.delete(1.0,'end')
                long_input.insert(INSERT,
"加密后的密文如下，请选中后用CTRL+C快捷键复制。\n显示密文期间该输入框会被锁定，请点击左侧模式选择处选择“文本”类选项解锁:\n\n")
                long_input.insert(INSERT,enc_hex)
                long_input.configure(state='disabled')
            else:
                print(1)
                try:
                    with open(source_file.get(),'r',encoding=('utf-8')) as f:
                        cleartext = f.read()
                        f.close()
                    enc_hex = AES_encrypt_text(cleartext,password.get())
                    long_input.delete(1.0,'end')
                    long_input.insert(INSERT,
"加密后的密文如下，请选中后用CTRL+C快捷键复制。\n显示密文期间该输入框会被锁定，请点击左侧模式选择处选择“文本”类选项解锁:\n\n")
                    long_input.insert(INSERT,enc_hex)
                    long_input.configure(state='disabled')
                except Exception as e:
                    messagebox.showerror("加密失败","请检查是文本文件是否存在、是否含有非法字符\n"+"错误信息"+str(e))
        elif m == 3:
            if len(long_input.get(1.0,'end')) > 1:
                try:
                    enctext = long_input.get(1.0,'end')
                    cleartext = AES_decrypt_text(enctext,password.get())
                    long_input.delete(1.0,'end')
                    long_input.insert(INSERT,
"解密后的明文如下，请选中后用CTRL+C快捷键复制。\n显示明文期间该输入框会被锁定，请点击左侧模式选择处选择“文本”类选项解锁:\n\n")
                    long_input.insert(INSERT,cleartext)
                    long_input.configure(state='disabled')
                except ValueError:
                    messagebox.showerror("解密失败","可能是密码错误，或者复制错了密文（多复制，少复制，复制到了空格等隐形字符）")
                except Exception as e:
                    messagebox.showerror("解密失败","错误信息"+str(e))
            else:
                try:
                    with open(source_file.get(),'r',encoding='utf-8') as f:
                        enctext = f.read()
                        f.close()
                    cleartext = AES_decrypt_text(enctext,password.get())
                    long_input.delete(1.0,'end')
                    long_input.insert(INSERT,
"解密后的明文如下，请选中后用CTRL+C快捷键复制。\n显示明文期间该输入框会被锁定，请点击左侧模式选择处选择“文本”类选项解锁:\n\n")
                    long_input.insert(INSERT,cleartext)
                    long_input.configure(state='disabled')
                except ValueError:
                    messagebox.showerror("解密失败",
"可能是密码错误，该文件不是文本文件，该文件含有非法字符,或该文件含有不全的密文或密文以外的字符")
                except Exception as e:
                    messagebox.showerror("解密失败","错误信息"+str(e))
        elif m == 4:
            dire = os.path.dirname(des_file_1.get())
            dire = dire + "\\"
            tsemode = key_len.get()
            tsemode = tsemode.replace(" ",'')
            tsemode = tsemode.replace("\n",'')
            if not tsemode in ['平级模式','上下级模式']: 
                messagebox.showerror("模式错误","模式只能是“平级模式”或“上下级模式”")
            else:
                try:
                    text_split_encrypt(source_file.get(),dire,des_file_1.get(),tsemode)
                except TypeError:
                    messagebox.showerror("格式错误","请确定要操作的文件是txt文件且内容符合格式需求")
                except FileNotFoundError:
                    messagebox.showerror("加密失败","请确认要加密的的文件存在，且目标文件不为空")
                except Exception as e:
                    messagebox.showerror("加密失败","错误信息"+str(e))
                else:
                    messagebox.showinfo("加密成功","加密成功")
        else:
            dire = working_dir.get()
            if dire[-1]!="\\":
                dire = dire + "\\"
            try:
                AES_mult_decrypt(password.get(),source_file.get(),dire)
            except TypeError:
                messagebox.showerror("解密失败","请确认这是一个“多密码加密”文件")
            except ValueError:
                messagebox.showerror("解密失败","密码错误")
            except Exception as e:
                messagebox.showerror("加密失败","错误信息"+str(e))
            else:
                messagebox.showinfo("解密成功","解密成功")
        return 0
    
    #按钮
    en_de_btn = Button(root,text="加密",command=btnfunc)
    en_de_btn.grid(row = 4,columnspan=2 ,sticky='wens')
    #大型文本输入框Frame
    text_input_frame = Frame(root)
    text_input_frame.grid(row=0,column = 1,sticky='wens')
    long_input = Text(text_input_frame,height=7,width=50) # 获取输入看准这个
    long_input_label = Label(text_input_frame,text="文本加密/解密输入框")
    long_input_label.pack(expand=True)
    long_input.pack(expand=True)
    long_input.configure(state='disabled')
    #frame 结束
    #小型输入
    #总Frame
    #0:标签Frame：
    text_frame = Frame(root)
    text_frame.grid(row=1,column=0,sticky='wens')
    
    working_dir_text = Label(text_frame,text="输入解密后文件的存放文件夹路径:")
    working_dir_text.pack(expand=True)
    des_file_text = Label(text_frame,text="输入加密后的目标文件完整路径:")
    des_file_text.pack(expand=True)
    source_file_text = Label(text_frame,text="输入要读取的源文件完整路径:")
    source_file_text.pack(expand=True)
    password_text = Label(text_frame,text="输入密码:")
    password_text.pack(expand=True)
    key_len_text = Label(text_frame,text="输入密钥长度:")
    key_len_text.pack(expand=True)
    #1:输入框Frame:
    entry_frame = Frame(root)
    entry_frame.grid(row=1,column=1,sticky='wens')
    def select_dir():
        working_dir.set(filedialog.askdirectory(initialdir = "/",title = "选择用于保存解密目标文件的文件夹"))
        return 0
    working_dir_1 = Button(entry_frame,text="选择保存文件夹",command=select_dir)
    des_file = Button(entry_frame,text="保存文件",command=browseFiles_1)
    source_file_1 = Button(entry_frame,text="选择文件",command=browseFiles)
    password = Entry(entry_frame,width=50,show='*')
    key_len = Entry(entry_frame,width=50,show='*')
    
    working_dir_1.pack(expand=True)
    des_file.pack(expand=True)
    source_file_1.pack(expand=True)
    password.pack(expand=True)
    key_len.pack(expand=True)
    
    #小型输入结束
    #模式选择Frame定义
    mode_select_frame = Frame(root)
    mode_select_frame.grid(row = 0,column = 0,sticky='wens')
    mode = IntVar()
    rbtnlist = []
    for i in range(6):
        rbtnlist.append(Radiobutton(mode_select_frame, text=mode_list[i], 
                                    variable=mode, value=i,command=chbtntxt))
        rbtnlist[i].pack(expand=True)
    #定义结束
    root.mainloop()
    return 0

def RSA_window():
    global imported_key
    imported_key = None
    #该函数的全局变量们:
    #############################
    root = Tk()
    root.title("RSA加密/解密")
    #第一个Frame，放置在root左上角，里面放着用于生成密钥的组件
    key_gen_frame = Frame(root)
    key_gen_frame.grid(row=0,column=0,padx=10,pady=10)
    #文字描述
    key_gen_frame_label = Label(key_gen_frame,text='在这里生成或导入密钥')
    key_gen_frame_label.pack(expand=True)
    key_gen_len_text = Label(key_gen_frame,text="输入密钥长度，只能是1024，2048，3072和4096：")
    key_gen_len_text.pack(expand=True)
    key_gen_len_input = Entry(key_gen_frame,width=40)
    key_gen_len_input.pack(expand=True)
    key_gen_pass_text = Label(key_gen_frame,text="输入密码以加密生成的RSA密钥，或用以解锁导入的密钥")
    key_gen_pass_text.pack(expand=True)
    key_gen_pass_input = Entry(key_gen_frame,width=40,show="*")
    key_gen_pass_input.pack(expand=True)
    def generate_and_save_key(int_str,passphrase):
        try:
            a = int(int_str)
            if a not in[1024,2048,3072,4096]:
                messagebox.showerror("密钥长度错误","请仅输入“1024”，“2048”，“3072”，或“4096”")
                return 0
        except:
            messagebox.showerror("密钥长度错误","请仅输入“1024”，“2048”，“3072”，或“4096”")
            return 0
        files = [('RSA密钥文件', '*.key'),('所有文件', '*.*')]
        key_loc = filedialog.asksaveasfilename(initialdir = "/",title = "密钥保存为",
                                        filetypes = files, defaultextension = files)
        if len(key_loc) < 2:
            messagebox.showwarning("未选择文件","您没有选择保存文件地址")
            return 0
        if len(passphrase)<=1:
            passphrase = None
        try:
            global imported_key
            key = RSA_key_gen(key_loc,passphrase,a)
            imported_key = key[0]
        except Exception as e:
            messagebox.showerror("密钥生成失败",str(e))
        else:
            messagebox.showinfo("密钥生成成功","生成成功，注意保护好自己的密钥")
        
        return 0
    key_gen_btn = Button(key_gen_frame,text="生成并保存密钥对",
                         command=lambda:generate_and_save_key(key_gen_len_input.get(),
                                                              key_gen_pass_input.get()))
    key_gen_btn.pack(expand=True)
    def key_read_func(passphrase):
        global imported_key
        files = [('RSA公钥文件', '*.pub'),('RSA私钥文件', '*.pri'),('所有文件', '*.*')]
        key_loc = filedialog.askopenfilename(initialdir = "/",title = "导入密钥",
                                        filetypes = files, defaultextension = files)
        if len(passphrase) <=1:
            passphrase = None
        try:
            imported_key = RSA_key_read(key_loc,passphrase)
        except Exception as e:
            messagebox.showerror("密钥导入失败",str(e))
        else:
            messagebox.showinfo("密钥导入成功","密钥导入成功")
        return 0
    key_read_btn = Button(key_gen_frame,text="导入密钥",
                         command=lambda:key_read_func(key_gen_pass_input.get()))
    key_read_btn.pack(expand=True)
    #第一个Frame结束
    #第二个Frame：文本加解密Frame
    text_operation_frame = Frame(root)
    text_operation_frame.grid(row=0,column=1,padx=10,pady=10)
    text_operation_frame_label = Label(text_operation_frame,text="在这里对文本进行操作")
    text_operation_frame_label.grid(row=0,columnspan=2)
    #6个tickbox：
    text_operation_mode_list = ["加密","解密","签名","认证签名"]
    fot_list = ["文本文件","文本输入"]
    t_operation = IntVar()
    text_operation_tickboxs = []
    def change_text_op_state():
        c = t_operation.get()
        text_input.delete(1.0,END)
        text_result.configure(state="normal")
        text_result.delete(1.0,END)
        a = ["加密","解密","签名","认证签名"]
        b = ["密文","原文","签名结果","输入待认证的签名"]
        s = ['disabled','normal']
        text_input_text.configure(text="输入待"+a[c]+"的文本")
        result_display_text.configure(text=b[c])
        text_result.configure(state=s[int(c/3)])
        return 0
    text_input_text = Label(text_operation_frame,text="输入待加密的文本")
    text_input_text.grid(row=1,column=1)
    text_input = Text(text_operation_frame,width = 50,height=4,state='normal')
    text_input.grid(row = 2,column=1,rowspan=2)
    
    result_display_text = Label(text_operation_frame,text="密文")
    result_display_text.grid(row=4,column=1)
    text_result = Text(text_operation_frame,width = 50,height=4,state='disabled')
    text_result.grid(row = 5,column=1,rowspan=2)
    def t_begin_func():
        global imported_key
        key = imported_key
        if key is None:
            messagebox.showerror("无密钥","尚未导入或生成密钥")
            return 0
        state_int = t_operation.get()
        cleartext = text_input.get(1.0,END)
        cleartext = cleartext.encode()
        if state_int == 0:
            if key.has_private():
                key = imported_key.public_key()
            try:
                ciphertext = RSA_encrypt_bit(cleartext,key)
                text_result.configure(state='normal')
                text_result.insert(INSERT,ciphertext.hex())
                text_result.configure(state='disabled')
            except Exception as e:
                messagebox.showerror("加密失败",str(e))
        elif state_int == 1:
            try:
                ciphertext = bytes.fromhex(text_input.get(1.0,END).replace(' ',''))
            except:
                messagebox.showerror("解密失败","请确认只复制密文部分而不带任何其它字符")
                return 0
            try:
                cleartext = RSA_decrypt_bit(ciphertext,key)
                cleartext = cleartext.decode()
            except:
                messagebox.showerror("解密失败","请确认密钥正确")
            else:
                text_result.configure(state='normal')
                text_result.insert(INSERT,cleartext)
                text_result.configure(state='disabled')
        elif state_int == 2:
            if not key.has_private():
                messagebox.showerror("签名失败","需要私钥才能签名，请导入.pri文件")
                return 0
            else:
                signature = RSA_sign_bit(cleartext,key)
                text_result.configure(state='normal')
                text_result.insert(INSERT,signature)
                text_result.configure(state='disabled')
        elif state_int == 3:
            if key.has_private():
                key = key.public_key()
            try:
                signature = text_result.get(1.0,END)
                signature = bytes.fromhex(signature)
            except:
                messagebox.showerror("验证失败","请确认签名框内只有签名而不带任何其它字符")
                return 0
            if RSA_verify_bit(cleartext,signature.hex(),key):
                messagebox.showinfo("验证成功","签名验证成功，文本确实来自签名发布者")
            else:
                messagebox.showerror("验证失败","签名验证失败，无法验证文本确实来自签名发布者")
        return 0
    t_begin = Button(text_operation_frame,text="操作",command=t_begin_func)
    t_begin.grid(row=6)
    for i in range(4):
        text_operation_tickboxs.append(Radiobutton(text_operation_frame, 
                                                   text=text_operation_mode_list[i], 
                                    variable=t_operation,value=i,command=change_text_op_state
                                    ))
        text_operation_tickboxs[i].grid(row=(i+1))
        
    #第二个Frame结束
    #第三个Frame：文件操作Frame
    file_frame = Frame(root)
    file_frame.grid(row=1,column=0,padx=10,pady=10)
    #一些子frame
    file_mode_frame = Frame(file_frame)
    file_mode_frame.grid(row=0,column=0)
    file_btn_frame = Frame(file_frame)
    file_btn_frame.grid(row=0,column=1)
    #局部变量们
    f_mode_var = IntVar()
    opensigloc = StringVar()
    savesigloc = StringVar()
    savedir = StringVar()
    openfilepath = StringVar()
    saveasfile = StringVar()
    def modify_var():
        m = f_mode_var.get()
        opensigloc.set("")
        savesigloc.set("")
        savedir.set("")
        openfilepath.set("")
        saveasfile.set("")
        if not m in [0,2]:
            file_btn[1].configure(state='disabled')
        else:
            file_btn[1].configure(state='normal')
        if not m in [1,3]:
            file_btn[2].configure(state='disabled')
        else:
            file_btn[2].configure(state='normal')
        if not m in [4]:
            file_btn[3].configure(state='disabled')
        else:
            file_btn[3].configure(state='normal')
        if not m in [5]:
            file_btn[4].configure(state='disabled')
        else:
            file_btn[4].configure(state='normal')
        return 0
    f_mode = []
    f_mode_text = ["加密（混合）（快）","解密（混合）（快）","加密（纯RSA）（慢）","解密（纯RSA）（慢）","验证签名文件","生成签名文件"]
    for i in range(len(f_mode_text)):
        f_mode.append(Radiobutton(file_mode_frame,
                                text=f_mode_text[i],
                                variable=f_mode_var, value=i,command=modify_var
                                ))
        f_mode[i].pack()
    def f0():
        files = [('Gacar普通加密文件', '*.gac'),
                 ('Gacar多密码加密文件', '*.gacm'), ('所有文件', '*.*')]
        openfilepath.set(filedialog.askopenfilename(initialdir="/", title="选择打开的文件", filetypes=files))
    def f2():
        savedir.set(filedialog.askdirectory(initialdir="/",mustexist=True, title="选择保存文件夹"))
    def f1():
        files = [('Gacar普通加密文件', '*.gac'),
                 ('Gacar多密码加密文件', '*.gacm'), ('所有文件', '*.*')]
        saveasfile.set(filedialog.asksaveasfilename(initialdir="/", title="保存为",
                                                    filetypes=files, defaultextension=files))
    def f3():
        files = [('签名文件', '*.sig'), ('文本文件', '*.txt'), ('所有文件', '*.*')]
        opensigloc.set(filedialog.askopenfilename(initialdir="/", title="选择导入的签名", filetypes=files))
    def f4():
        files = [('签名文件', '*.sig'), ('文本文件', '*.txt'), ('所有文件', '*.*')]
        savesigloc.set(filedialog.asksaveasfilename(initialdir="/", title="签名保存为", filetypes=files,defaultextension = files))
        print(savesigloc.get())
    def f5():
        if imported_key is None:
            messagebox.showerror("操作失败","未生成或导入任何密钥")
            return 0
        m = f_mode_var.get()
        if   m == 0:
            if len(openfilepath.get())<=1 or len(saveasfile.get())<=1:
                messagebox.showerror("加密失败","未选择要加密的文件和保存位置")
                return 0
            else:
                try:
                    hybrid_encrypt_file(openfilepath.get(), saveasfile.get(), imported_key)
                except Exception as e:
                    messagebox.showerror("加密失败",str(e))
                    return 0
                else:
                    messagebox.showinfo("加密成功","加密成功")
        elif m == 1:
            if len(openfilepath.get())<=1 or len(savedir.get())<=1:
                messagebox.showerror("解密失败","未选择要解密的文件和保存位置")
                return 0
            elif not imported_key.has_private():
                messagebox.showerror("解密失败", "您导入的不是私钥，需要私钥才能解密文件")
                return 0
            else:
                try:
                    hybrid_decrypt_file(openfilepath.get(), savedir.get(), imported_key)
                except ValueError:
                    messagebox.showerror("解密失败", "密钥不正确")
                except Exception as e:
                    messagebox.showerror("解密失败",str(e))
                    return 0
                else:
                    messagebox.showinfo("解密成功","解密成功")
        elif m == 2:
            if len(openfilepath.get())<=1 or len(saveasfile.get())<=1:
                messagebox.showerror("加密失败","未选择要加密的文件和保存位置")
                return 0
            else:
                try:
                    RSA_encrypt_file(openfilepath.get(), saveasfile.get(), imported_key)
                except Exception as e:
                    messagebox.showerror("加密失败",str(e))
                    return 0
                else:
                    messagebox.showinfo("加密成功","加密成功")
        elif m == 3:
            if len(openfilepath.get())<=1 or len(savedir.get())<=1:
                messagebox.showerror("解密失败","未选择要解密的文件和保存位置")
                return 0
            elif not imported_key.has_private():
                messagebox.showerror("解密失败", "您导入的不是私钥，需要私钥才能解密文件")
                return 0
            else:
                try:
                    RSA_decrypt_file(openfilepath.get(), savedir.get(), imported_key)
                except ValueError:
                    messagebox.showerror("解密失败", "密钥不正确")
                except Exception as e:
                    messagebox.showerror("解密失败",str(e))
                    return 0
                else:
                    messagebox.showinfo("解密成功","解密成功")
        elif m == 4:
            if len(openfilepath.get())<=1 or len(opensigloc.get())<=1:
                messagebox.showerror("签名验证失败","未选择要验证的文件或签名文件")
                return 0
            else:
                try:
                    A = RSA_verify_file(openfilepath.get(), imported_key,sf=opensigloc.get())
                except Exception as e:
                    messagebox.showerror("签名验证失败",str(e))
                    return 0
                else:
                    if A:
                        messagebox.showinfo("验证成功","文件签名正确")
                    else:
                        messagebox.showerror("签名验证失败","无法验证文件来自签名发布者")
        elif m == 5:
            if len(openfilepath.get())<=1 or len(savesigloc.get())<=1:
                messagebox.showerror("签名生成失败","未选择要验证的文件或签名文件的保存位置")
                return 0
            elif not imported_key.has_private():
                messagebox.showerror("签名生成失败", "您导入的不是私钥，需要私钥才能签名文件")
                return 0
            else:
                try:
                    RSA_sign_file(openfilepath.get(), imported_key,sf=savesigloc.get())
                except Exception as e:
                    messagebox.showerror("签名生成失败",str(e))
                    return 0
                else:
                    messagebox.showinfo("签名生成成功","签名生成成功")
            return 0
        return None
    file_btn = []
    file_btn_text = ["打开文件","选择位置保存加密后的文件","选择文件夹保存解密后的文件","导入签名","选择签名保存位置","进行所选操作"]
    for i in range(6):
        file_btn.append(Button(file_btn_frame,text=file_btn_text[i],width=25))
        file_btn[i].pack()
        if i == 0:
            file_btn[0].configure(command=f0)
        elif i == 1:
            file_btn[1].configure(command=f1)
        elif i == 2:
            file_btn[2].configure(command=f2)
        elif i == 3:
            file_btn[3].configure(command=f3)
        elif i == 4:
            file_btn[4].configure(command=f4)
        elif i == 5:
            file_btn[5].configure(command=f5)

    #第三个Frame结束
    root.mainloop()
    del imported_key
    return 0

def Advanced_window():
    root = Tk()
    root.title("高级模式")
    #第一个frame，多密码加密Frame
    muti_pass_frame = Frame(root)
    muti_pass_frame.grid(row=0,column=0)
    muti_pass_frame_text = Label(muti_pass_frame,text="多密码加密")
    muti_pass_frame_text.pack()
    radiobtnframe = Frame(muti_pass_frame)
    radiobtnframe.pack()
    radiobtn = []
    global data_list
    data_list = []
    key_len = IntVar()
    for i in [16,24,32]:
        radiobtn.append(Radiobutton(radiobtnframe,text="密钥长"+str(i),variable=key_len,value=i))
        radiobtn[-1].pack(side=LEFT)
    enterpasstext = Label(muti_pass_frame,text="在这里输入加密这个文件的密码")
    enterpasstext.pack()
    password = Entry(muti_pass_frame)
    password.pack()
    added_file = StringVar()
    def add_file():
        global data_list
        added_file.set(filedialog.askopenfilename(initialdir="/", title="添加一个文件", filetypes=[('所有文件', '*.*')]))
        if len(added_file.get()) < 2:
            messagebox.showinfo("取消添加文件","您放弃了添加该文件")
            return 0
        else:
            data_list.append([added_file.get(),password.get(),get_random_bytes(key_len.get())])
        return 0
    muti_enc_select = Button(muti_pass_frame, text="添加一个文件", command=add_file)
    muti_enc_select.pack()
    save_file = StringVar()
    def saveas():
        save_file.set(filedialog.asksaveasfilename(initialdir="/", title="保存为",
                                                   filetypes=[('多密码加密文件', '*.gacm'), ('所有文件', '*.*')],
                                                   defaultextension=[('多密码加密文件', '*.gacm'), ('所有文件', '*.*')]))
        return 0
    saveasfile = Button(muti_pass_frame, text="选择加密后文件的保存位置",command = saveas )
    saveasfile.pack()
    def multi_enc():
        global data_list
        if data_list == [] or len(save_file.get())<=1:
            messagebox.showerror("加密失败","请至少添加一个文件，并指定加密后文件的位置")
            return 0
        elif messagebox.askyesno("是否加密","当前共"+str(len(data_list))+"个要加密的文件，是否继续？"):
            dire = os.path.dirname(save_file.get())
            dire = dire + "\\"
            try:
                AES_mult_encrypt(data_list,dire,save_file.get())
            except ValueError:
                messagebox.showerror("加密失败","您其中添加的一个文件过大")
                messagebox.showinfo("清除列表","您的即将加密的文件的列表将被清空以移除问题文件")
                data_list = []
                return 0
            except Exception as e:
                messagebox.showerror("加密失败",str(e))
            else:
                messagebox.showinfo("加密成功", "加密成功")
        return 0
    enc_btn = Button(muti_pass_frame,text="加密",command=multi_enc)
    enc_btn.pack()
    #第一个Frame结束
    #第二个Frame：多密码解密Frame
    decrypt_multi = Frame(root)
    decrypt_multi.grid(row=0,column=1)
    decrypt_multi_text = Label(decrypt_multi,text="多密码文件解密")
    decrypt_multi_text.pack()
    pass_enter_text = Label(decrypt_multi,text="输入密码")
    pass_enter_text.pack()
    pass_enter = Entry(decrypt_multi)
    pass_enter.pack()
    def multi_de_btn_func(password):
        a = filedialog.askopenfilename(initialdir="/", title="打开加密文件" , filetypes=[('多密码加密文件', '*.gacm'),('所有文件', '*.*')])
        if len(a)<2:
            messagebox.showerror("未选择文件","未选择文件，解密失败")
            return 0
        b = filedialog.askdirectory(initialdir="/",title="选择保存文件夹",mustexist=True)
        if len(b)<2:
            messagebox.showerror("未选择文件夹","未选择目标文件夹，解密失败")
            return 0
        try:
            if b[-1] not in ["\\", "/"]:
                b = b + "\\"
            AES_mult_decrypt(password, a, b)
        except TypeError:
            messagebox.showerror("文件类型错误","这不是一个多密码加密文件")
            return 0
        except ValueError:
            messagebox.showerror("密码错误","您输入的密码无法打开该多密码文件内的任何一个子文件")
            return 0
        except Exception as e:
            messagebox.showerror("解密失败",str(e))
            return 0
        else:
            messagebox.showinfo("解密成功","Success")
        return 0
    multi_de_btn = Button(decrypt_multi,text="点击解密",command=lambda:multi_de_btn_func(pass_enter.get()))
    multi_de_btn.pack()
    #第二个Frame结束
    #第三个Frame：文本隐写与读取
    hidmsgframe=Frame(root)
    hidmsgframe.grid(row=1,column=0,columnspan=2)
    hidbtnframe = Frame(hidmsgframe)
    hidbtnframe.grid(row=0,column=0)
    textframe=Frame(hidmsgframe)
    textframe.grid(row=0,column=1,columnspan=3)
    text_input = Text(textframe,width=50,height=10)
    text_input_label = Label(textframe,text="在这个文本框内输入要藏进图片内的文本，或打开藏有文本的图片，内容会在这里显示")
    text_input_label.pack()
    text_input.pack()
    def read_img():
        read_img_loc.set(filedialog.askopenfilename(initialdir="/",title="打开PNG文件",filetypes=[('PNG图片','*.png')]))
        if len(read_img_loc.get())<2:
            messagebox.showinfo("未选文件", "您没有选择文件或取消选择了文件")
            read_img_loc.set("")
        return 0
    read_img_loc = StringVar()
    readimg = Button(hidbtnframe,width=15,text="打开图片",command=read_img)
    readimg.pack()
    def save_img():
        if len(read_img_loc.get())<2:
            messagebox.showerror("没有图片","您没有选择任何图片")
            return 0
        elif len(text_input.get(1.0,END)) < 2:
            messagebox.showerror("没有信息","文本输入框似乎是空的")
            return 0
        else:
            saveaspng = filedialog.asksaveasfilename(title="保存为", initialdir="/", filetypes=[("PNG图片",'*.png')],  defaultextension=("PNG图片",'*.png'))
            if len(saveaspng) < 2:
                messagebox.showerror("保存失败","您没有指定保存位置")
                return 0
            try:
                lsb_hide_msg(read_img_loc.get(), saveaspng, text_input.get(1.0,END))
            except ValueError:
                messagebox.showerror("保存失败", "图片太小或您输入的文本太大，请考虑删节您输入的文本或更换一张更大的图片")
                if os.path.exists(saveaspng):
                    os.remove(saveaspng)
            except Exception as e:
                messagebox.showerror("保存失败", "PNG源文件无法打开，您打开的原文件可能已经损坏或不是PNG类型文件"+'\n详细信息：' + str(e))
                if os.path.exists(saveaspng):
                    os.remove(saveaspng)
            else:
                messagebox.showinfo("保存成功", "保存成功")
        return 0
    save_img_btn = Button(hidbtnframe,width=15,text="隐藏文本并保存",command=save_img)
    save_img_btn.pack()
    def decode_text():
        if len(read_img_loc.get())<2:
            messagebox.showerror("没有图片","您没有选择任何图片")
            return 0
        else:
            try:
                a = lsb_show_msg(read_img_loc.get())
            except ValueError:
                messagebox.showerror("解读失败","图片似乎不含文本")
            except UnicodeError:
                messagebox.showerror("解读失败","找到了隐藏的信息却无法解读，可能由于压缩等原因信息已损坏")
            except Exception as e:
                messagebox.showerror("解读失败", "PNG源文件无法打开，您打开的原文件可能已经损坏或不是PNG类型文件" + '\n详细信息：' + str(e))
            else:
                text_input.delete(1.0, END)
                text_input.insert(INSERT, a)
                messagebox.showinfo("解读成功","文本已显示至文本输入框内")
        return 0
    decode_text_btn = Button(hidbtnframe,width=15,text="阅读隐藏的文本",command=decode_text)
    decode_text_btn.pack()
    #第三个frame结束
    root.mainloop()
    del data_list
    return 0

r = Tk()
r.title("GacarCrypt 加密软件")
btn = []

def A():
    r.destroy()
    AES_window()
def B():
    r.destroy()
    RSA_window()
def C():
    r.destroy()
    Advanced_window()

commandlist=[A,B,C,r.destroy]
text = ["AES加密","RSA加密","进阶模式","退出"]
for i in range(4):
    btn.append(Button(r,width=20,text=text[i],command=commandlist[i]))
    btn[-1].grid(row=int(i/2), column=i%2)
messagebox.showinfo("欢迎","欢迎来到GacarCrypt加密软件！您可以在此软件中加密您的敏感文件，生成并管理RSA密钥，并体验许多高级功能")
r.mainloop()