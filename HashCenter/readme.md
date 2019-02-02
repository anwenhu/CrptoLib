# HashCenter集成哈希模块

   ## 1. 引用头文件"HashCenter.h"
    #include "HashCenter.h"

   ## 2. 创建HashCenter对象
   > 1. HashCenter类的构造函数接受一个参数。
   > 2. 该参数用于指定hash函数，值为"MD5"指定MD5作为hash函数，值为"SHA512"指定SHA512作为hash函数。
   
    HashCenter hashcenter("MD5");
   
   ## 3. 利用创建的HashCenter对象进行Hash操作
   > 1. 使用gethash成员函数获得输入原始消息的hash值
   > 2. 

   
