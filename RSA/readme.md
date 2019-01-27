# RSA模块

   ## 1. 引用头文件"RSA.py"
    import RSA

   ## 2. 创建一个RSA对象
    rsa = RSA.RSA()

   ## 3. 分别使用generatePubKey和generatePrivKey成员方法生成RSA加密的公钥(n,e)和私钥(n,d)
   > 1. generatePubKey成员方法返回生成的公钥(n,e)
   > 2. generatePrivKey成员方法返回生成的私钥(n,d)
    
    pubkey = rsa.generatePubKey()      #生成公钥pubkey=(n,e)
    privkey = rsa.generatePrivKey()    #生成私钥privkey=(n,d)
   
    
   ## 4. 使用encrypt成员方法进行RSA加密
   > 1. encrypt成员方法的唯一参数为十进制的明文输入
   > 2. 返回值为RSA加密结果 
    
    crpt = rsa.encrypt(plain)

   ## 5. 使用decrypt成员方法进行RSA解密
   > 1. decrypt成员方法的唯一参数为十进制的密文输入
   > 2. 返回值为RSA解密结果
     
    plain = rsa.decrypt(crpt)
   
   ## 附注: 
   > 1. example.py中提供了一个使用RSA模块进行加密和解密的完整示例。

