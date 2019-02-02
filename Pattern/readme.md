# Pattern分组加密集成模块

   ## 1. 引用头文件"Pattern.h"
    #include "Pattern.h"

   ## 2. 创建一个Pattern对象
   > 1. 初始化一个Pattern对象需要提供两个参数，这两个参数分别指定分组密码种类和加密模式。
   > 2. 第一个参数指定分组密码种类，其值为"AES"或者"DES"，分别指定DES和AES加密。
   > 3. 第二个参数指定分组密码的加密模式，其值为"ECB","CBC","CFB","OFB","CTR"，分别指定对应的分组加密模式。
   
    Pattern pat0=Pattern("AES","CTR");   //初始化pat0为使用AES分组密码和CTR加密模式的Pattern对象
	  
    
   ## 3. 改变一个已经创建的Pattern对象的加密模式
   > 1. 使用reset成员方法来改变加密模式。
   > 2. 同构造函数相同，第一个参数指定分组密码种类，其值为"AES"或者"DES"，分别指定DES和AES加密。
   > 3. 同构造函数相同，第二个参数指定分组密码的加密模式，其值为"ECB","CBC","CFB","OFB","CTR"，分别指定对应的分组加密模式。
   
    pat0.reset("DES","ECB");             //将pat0对象修改为使用AES分组密码和ECB加密模式的Pattern对象
    
   ## 4. 使用Pattern对象进行加密
   > 1. 使用encrypt成员方法来进行字符串加密。
   > 2. 第一个参数为明文字符串，长度不限。
   > 3. 第二个参数为密钥字符串，若为DES加密，则该密钥字符串的长度必须为8；若为AES加密，则该密钥字符串的长度必须为16。
   > 4. 第三个参数为偏移向量字符串，若为DES加密，则该偏移向量的长度必须为8；若为AES加密，则该偏移向量的长度必须为16；特别地，当使用ECB加密时，由于ECB加密中不使用偏移向量，因此该参数取值可以为任意字符串。
   > 5. 第四个参数为输出格式指定，取值为"0x"时指定输出密文格式为十六进制；取值为"0b"时指定输出密文格式为二进制。
   
    string plain="abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghab";
    string key="abcdefghabcdefgh";   //aes使用32位十六进制密钥，每个字母对应两位二进制 
    string vec="abcdefghabcdefgh";
  
    string crpt0=pat0.encrypt(plain, key, vec, "0x");
    cout<<"ECB加密得到的密文="<<crpt0<<endl<<endl;
	
   
   ## 5. 使用Pattern对象进行解密
   > 1. 使用decrypt成员方法来进行字符串加密。
   > 2. 第一个参数为密文字符串，长度不限。
   > 3. 第二个参数为密钥字符串，若为DES解密，则该密钥字符串的长度必须为8；若为AES解密，则该密钥字符串的长度必须为16。
   > 4. 第三个参数为偏移向量字符串，若为DES解密，则该偏移向量的长度必须为8；若为AES解密，则该偏移向量的长度必须为16；特别地，当使用ECB解密时，由于ECB解密中不使用偏移向量，因此该参数取值可以为任意字符串。
   > 5. 第四个参数为输出格式指定，取值为"0x"时指定输出明文格式为十六进制；取值为"0b"时指定输出明文格式为二进制。
   
    string result=pat0.decrypt(crpt0, key, vec, "0x");
    cout<<"ECB解密得到的密文="<<result<<endl<<endl;

  
