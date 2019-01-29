# Diffie-Hellman密钥交换模块

   ## 1. 引用头文件"DH.py"
    import DH

   ## 2. 创建两个DeffieHellman对象A和B，作为密钥交换的两方
    A = DH.DeffieHellman()
    B = DH.DeffieHellman()

   ## 3. 由其中的一方A调用generateArg成员方法，生成Diffie-Hellman密钥交换的共享参数——素数q及其本原根a
   > 1. generateArg成员方法返回生成的DH密钥交换的公共参数(q,a)
    
    q, a = A.generateArg()
   
    
   ## 4. 密钥交换的双方A和B，共享上述素数q和本原根a，根据共享参数q和a，调用generateKey成员方法生成各自的公钥和私钥，并共享A,B各自的公钥Ya，Yb
   > 1. generateKey成员方法的两个参数依次为共享参数——素数q和本原根a
   > 2. 返回值为生成的公钥 
    
    Ya = A.generateKey(q,a)
    Yb = B.generateKey(q,a)

   ## 5. 双方根据对方的公钥，调用getKey成员方法计算出共享密钥并输出
   > 1. getKey成员方法的唯一参数是密钥交换中另一方的公钥
   > 2. 返回值为共享的真实密钥
     
    keya=A.getKey(Yb)
    keyb=B.getKey(Ya)
   
   ## 附注: 
   > 1. example.py中提供了一个使用DH密钥交换模块的示例程序。


