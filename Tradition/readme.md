# Tradition传统密码集成模块

   ## 1. 引用头文件"Tradition.h"
    #include "Tradition.h"

   ## 2. 创建一个Tradition对象
   > 1. Tradition类的对象可以进行默认初始化，即在初始化的时候无需提供任何的参数。
   > 2. Tradition类包含Caesar，仿射，Vigenere三种经典加密算法，根据这三种加密算法的定义，其的明文和密文字符串中均要求仅含26个英文字母。
   
    Tradition trad;
    
   ## 3. 进行Caesar加密和解密
   > 1. 使用caesar_encrypt成员函数进行加密，第一个参数为任意长度的明文字符串，第二个参数为一个整数密钥，返回加密得到的密文字符串。
   > 2. 使用caesar_decrypt成员函数进行解密，第一个参数为任意长度的密文字符串，第二个参数为一个整数密钥，返回解密得到的明文字符串。
   
    //Caesar
    string plain="abcdefghijklmnopqrstuvwxyz";
    string crpt;
    int key=3;
	
    crpt=trad.caesar_encrypt(plain,key);
    cout<<"Caesar encrypt = "<<crpt<<endl;
    plain=trad.caesar_decrypt(crpt,key);
    cout<<"Caesar decrypt = "<<plain<<endl;
 
   ## 4. 进行仿射加密和解密
   > 1. 仿射密码又被称为广义Caesar密码，仿射密码的密钥为(a,b)，对于每一个明文字母p，对应的密文字母c使用公式c=(ap+b)mod26计算得到。
   > 2. 使用corr_encrypt成员函数进行加密，第一个参数为任意长度的明文字符串，第二个参数和第三个参数分别为整数密钥a,b，返回加密得到的密文字符串。
   > 3. 使用corr_decrypt成员函数进行解密，第一个参数为任意长度的密文字符串，第二个参数和第三个参数分别为整数密钥a,b，返回解密得到的明文字符串。
   
    //Corr
    string plain1="abcdefghijklmnopqrstuvwxyz";
    string crpt1;
    int a=3, b=3;
	
    crpt1=trad.corr_encrypt(plain1,a,b);
    cout<<"Corr encrypt = "<<crpt1<<endl;
    plain1=trad.corr_decrypt(crpt1,a,b); 
    cout<<"Corr decrypt = "<<plain1<<endl;
    
   ## 5. 进行Vigenere加密和解密
   > 1. 使用vigenere_encrypt成员函数进行加密，第一个参数为任意长度的明文字符串，第二个参数为任意长度的密钥字符串，返回加密得到的密文字符串。
   > 2. 使用vigenere_decrypt成员函数进行解密，第一个参数为任意长度的密文字符串，第二个参数为任意长度的密钥字符串，返回解密得到的明文字符串。 
    
    //Vigenere
    string plain2="abcdefghijklmnopqrstuvwxyz";
    string crpt2;
    string key2="abcdefghijklmnopqrstuvwxyz";
	
    crpt2=trad.vigenere_encrypt(plain2,key2);
    cout<<"Vigenere encrypt = "<<crpt2<<endl;
    plain2=trad.vigenere_decrypt(crpt2,key2);
    cout<<"CVigenere decrypt = "<<plain2<<endl;
   
  
