# Elgamel模块

   ## 1. 引用头文件"Elgamel.py"
    import Elgamel as El

   ## 2. 创建一个Elgamel发送方对象和Elgamel接收方对象
   > 1. 首先使用Elgamel类的默认初始化函数初始化Elgamel
   > 2. 使用类的receiveClient方法将对象设置为接收方对象，receiveClient方法将生成Elgamel体系中的共享参数q, a, Y，并根据这些共享参数将对象设置为接收方对象：
   >> 参数列表：空； 返回值：(q, a, Y)，即生成的Elgamel密码体系中的由收发双方共享的参数
   > 3. 使用类的sendClient方法将对象设置为发送方对象，sendClient方法根据接收方设定的共享参数将对象设置为发送方对象：
   >> 参数列表: 3个参数依次为q, a, Y，这些参数由接收方调用的receiveClient方法返回； 返回值：空
    
    A = El.Elgamel()
    B = El.Elgamel()
    
    q, a, Y = B.receiveClient()
    A.sendClient(q,a,Y)

   ## 3. 使用encrypt方法进行Elgamel加密
   > 1. encrypt方法的参数为不大于共享参数q的十进制整数明文M
   > 2. 返回值为加密后的密文对(C1, C2)，其中C1, C2均为十进制整数
   
    crpt = A.encrypt(plain)


   ## 4. 使用decipher方法进行Elgamel解密
   > 1. decrypt方法的参数为Elgamel密文对(C1, C2)
   > 2. 返回值为解密后的十进制整数明文和加密密钥key的元组(M, key)
   
    plain = B.decipher(crpt)
    print("明文 = ", plain[0])
    print("密钥 = ", plain[1])

   ## 附注: 
   > 1. example.py中提供了一个使用DES模块加密和解密的完整示例。

