# HMAC 消息认证码(mac)模块

   ## 1. 引用头文件"HMAC.h"
    #include "HMAC.h"

   ## 2. 创建一个HMAC对象
    HMAC hmac=HMAC();

   ## 3. 使用getMac方法获取消息认证码mac
   > 1. 第一个参数为任意长度的原始十六进制或者二进制消息。
   > 2. 第二个参数为任意长度的原始十六进制或者二进制密钥。
   > 3. 第三个参数指定生成消息认证码(mac)使用的hash函数，"sha512"指定使用sha512 hash函数，"md5"指定使用md5 hash函数。
   > 4. 第四个参数指定输入格式，"0x"表示输入的原始消息为十六进制，"0b"表示输入的原始消息为二进制。
   > 5. 第五个参数指定输出格式，"0x"表示生成的消息认证码以十六进制返回，"0b"表示结果以二进制返回。
   
    string plain="616263";
    string key="616263";
    string result;
    
    //获取sha512 消息认证码
    result=hmac.getMac(plain,key,"sha512","0x","0x");
	  cout<<"sha512 mac result: "<<result<<endl;
	  
    //获取md5 消息认证码
	  result=hmac.getMac(plain,key,"md5","0x","0x");
	  cout<<"md5 mac result: "<<result<<endl;


   ## 附注: 
   > 1. example.cpp中提供了一个使用HMAC生成消息认证码(mac)操作的完整示例。HMAC example.txt中提供了一个sha512和md5生成的消息认证码的实例。
   > 2. 本模块的原始消息/密钥输入必须是长度不限的十六进制或者二进制，其他如字符串需要首先转化为十六进制或者二进制再输入。
