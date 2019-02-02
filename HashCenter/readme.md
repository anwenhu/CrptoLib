# HashCenter集成哈希模块

   ## 1. 引用头文件"HashCenter.h"
    #include "HashCenter.h"

   ## 2. 创建HashCenter对象
   > 1. HashCenter类的构造函数接受一个参数。
   > 2. 该参数用于指定hash函数，值为"MD5"指定MD5作为hash函数，值为"SHA512"指定SHA512作为hash函数。
   
    HashCenter hashcenter("MD5");
   
   ## 3. 利用创建的HashCenter对象进行Hash操作
   > 1. 使用gethash成员函数获得输入原始消息的hash值
   > 2. 该成员函数的第一个参数为原始消息
   > 3. 该成员函数的第二个参数用于指定输出格式，"0x"指定输出的hash结果为十六进制，"0b"指定输出的hash结果为二进制
   
    string infor="abcdefgh";
	 string md5_result=hashcenter.gethash(infor,"0x");
    
   ## 4. 改变HashCenter对象所使用的hash函数
   > 1. 使用reset重新设置所使用的hash函数
   > 2. 该成员函数的唯一参数为重新设置的hash函数种类，值为"MD5"指定MD5作为hash函数，值为"SHA512"指定SHA512作为hash函数。
   
    hashcenter.reset("SHA512");
	 string sha512_result=hashcenter.gethash(infor,"0x");
    
   ## 附注:
   > 1. example.cpp中提供了一个使用HashCenter模块的具体示例程序。

   
