#include "DES.h"
#include "AES.h"
#include <cstdlib>
#include <ctype.h>
#include <cmath>

using namespace std;

class Pattern
{
    public:
    //public functions
    Pattern(string crymode, string sysmode);                                 //Pattern: 初始化Pattern类并设定加密模式
    string encrypt(string input, string key, string vec, string outmode);    //encrypt: 根据输入的明文和密钥进行加密并返回密文
    string decrypt(string input, string key, string vec, string outmode);    //decrypt: 根据输入的密文和密钥进行解密并返回明文
    void reset(string crymode, string sysmode);                              //reset: 重新设置Pattern类的对象的加密模式

    private:
    //private variables
    string __crymode="DES";       //密码模式: DES或者AES
    string __sysmode="ECB";       //加密模式: ECB, CBC, CFB, OFB, CTR五种加密模式可选

    //private functions
    string __hexToBinary(string input);                        //__hexToBinary: 十六进制输入转换为二进制
    string __binToHexto(string input);                         //__binToHexto: 二进制输入转换为十六进制
    string __convert(string input);                            //__convert: 将用户输入的字符串转化为在内存中的二进制形式
    string __XOR(string a,string b);                           //__XOR: 将两个二进制字符串之间进行异或操作，并返回异或结果
    string __ECB(string input, string key, string vec, string crymode, string outmode, bool encrypt_or_decrypt); //__ECB: 根据明文和密钥进行ECB加密或者解密
    string __CBC(string input, string key, string vec, string crymode, string outmode, bool encrypt_or_decrypt); //__CBC: 根据明文和密钥进行CBC加密或者解密
    string __CFB(string input, string key, string vec, string crymode, string outmode, bool encrypt_or_decrypt); //__CFB: 根据明文和密钥进行CFB加密或者解密
    string __OFB(string input, string key, string vec, string crymode, string outmode, bool encrypt_or_decrypt); //__OFB: 根据明文和密钥进行OFB加密或者解密
    string __CTR(string input, string key, string vec, string crymode, string outmode, bool encrypt_or_decrypt); //__CTR: 根据明文和密钥进行CTR加密或者解密
    string __COUNTER(string lastcount);                        //__COUNTER: CTR模式中使用的计数器，获取下一个计数器的值
};

/*************************************** public functions **************************************/

/*1.
 *Pattern: 初始化Pattern类并设定加密模式
 *Param: crymode--指定分组密码，为"DES"或者"AES"； sysmode--指定分组加密模式，可选"ECB", "CBC", "CFB", "OFB", "CTR"
*/
Pattern::Pattern(string crymode, string sysmode)
{
    __crymode=crymode;
    __sysmode=sysmode;
}

/*2.
 *encrypt: 根据输入的明文和密钥进行加密并返回密文
 *Param: input--明文字符串，长度不限； key--密钥字符串，若为DES加密则长度必须为8，若为AES加密则长度必须为16
 *Return: 分组加密结果，即密文
*/
string Pattern::encrypt(string input, string key, string vec, string outmode)
{
    //1. 将用户输入的字符串明文和密钥转换为二进制形式
    input=__convert(input);
    key=__convert(key);
    vec=__convert(vec);

    //2. 根据用户初始化Pattern类时设定的加密模式，使用二进制的明文和密钥进行加密，并返回加密结果；outmode--加密结果输出格式指定，"0x"/"0b"指定十六进制/二进制输出； 
    if(__sysmode=="ECB")
    return __ECB(input, key, vec, __crymode, outmode, true);
    else if(__sysmode=="CBC")
    return __CBC(input, key, vec, __crymode, outmode, true);
    else if(__sysmode=="CFB")
    return __CFB(input, key, vec, __crymode, outmode, true);
    else if(__sysmode=="OFB")
    return __OFB(input, key, vec, __crymode, outmode, true);
    else if(__sysmode=="CTR")
    return __CTR(input, key, vec, __crymode, outmode, true);
    else
    throw "Invalid encrypt mode.";
}

/*3.
 *decrypt: 根据输入的密文和密钥进行解密并返回明文
 *Param: input--密文字符串，长度不限； key--密钥字符串，若为DES加密则长度必须为8，若为AES加密则长度必须为16；vec--除了ECB模式之外使用的偏移向量，在ECB中该参数不会被使用；outmode--加密结果输出格式指定，"0x"/"0b"指定十六进制/二进制输出； 
 *Return: 分组解密结果，即明文
*/
string Pattern::decrypt(string input, string key, string vec, string outmode)
{
    //1. 将用户输入的字符串密文和密钥转换为二进制形式
    input=__convert(input);
    key=__convert(key);
    vec=__convert(vec);

    //2. 根据用户初始化Pattern类时设定的解密模式，使用二进制的密文和密钥进行解密，并返回解密结果
    if(__sysmode=="ECB")
    return __ECB(input, key, vec, __crymode, outmode, false);
    else if(__sysmode=="CBC")
    return __CBC(input, key, vec, __crymode, outmode, false);
    else if(__sysmode=="CFB")
    return __CFB(input, key, vec, __crymode, outmode, false);
    else if(__sysmode=="OFB")
    return __OFB(input, key, vec, __crymode, outmode, false);
    else if(__sysmode=="CTR")
    return __CTR(input, key, vec, __crymode, outmode, false);
    else
    throw "Invalid encrypt mode.";
}

/*4.
 *reset: 重新设置Pattern类的对象的加密模式
 *Param: crymode--指定分组密码，为"DES"或者"AES"； sysmode--指定分组加密模式，可选"ECB", "CBC", "CFB", "OFB", "CTR"
 *Return: None
*/
void Pattern::reset(string crymode, string sysmode)
{
    __crymode=crymode;
    __sysmode=sysmode;
}

/*************************************** private functions **************************************/

/*1.
 *__hexToBinary: 该方法将十六进制字符串转化为二进制字符串（均不含前缀） 
 *Param: input--无前缀十六进制输入
 *Return：output--无前缀二进制输出
*/
string Pattern::__hexToBinary(string input)
{
    map<char,string> dic;         //十六进制数到二进制数的转换表
    dic['0']="0000"; dic['1']="0001"; dic['2']="0010"; dic['3']="0011"; dic['4']="0100"; dic['5']="0101"; dic['6']="0110"; dic['7']="0111"; dic['8']="1000"; dic['9']="1001"; dic['A']="1010"; dic['B']="1011"; dic['C']="1100"; dic['D']="1101"; dic['E']="1110"; dic['F']="1111";dic['a']="1010"; dic['b']="1011"; dic['c']="1100"; dic['d']="1101"; dic['e']="1110"; dic['f']="1111";

    string output;
    for(int i=0;i<input.size();i++)
    {
        output+=dic[input[i]];
    }
    return output;
}

/*2.
 *__binToHexto: 该方法将二进制字符串转化为十六进制字符串（均不含前缀）
 *Param: input--无前缀二进制输入
 *Return: output--无前缀十六进制输出
*/
string Pattern::__binToHexto(string input)
{
    map<string,string> redic;         //二进制数到十六进制数的转换表
    redic["0000"]="0"; redic["0001"]="1"; redic["0010"]="2"; redic["0011"]="3"; redic["0100"]="4"; redic["0101"]="5"; redic["0110"]="6"; redic["0111"]="7"; redic["1000"]="8"; redic["1001"]="9"; redic["1010"]="a"; redic["1011"]="b"; redic["1100"]="c"; redic["1101"]="d"; redic["1110"]="e"; redic["1111"]="f";

    string output;
    for(int i=0;i<input.size()/4;i++)  
    {
        string temp;
        for(int k=i*4;k<(i+1)*4;k++)
        {
            temp.push_back(input[k]);
        }
        output+=redic[temp];
    }
    return output;
}

/*3.
 *__convert: 将用户输入的字符串转化为在内存中的二进制形式
 *Param: input--用户输入的，字符串形式的明文，密文或者密钥
 *Return: 明文，密文或者密钥在内存中的二进制形式
*/
string Pattern::__convert(string input)
{
    //1. 将用户输入转化为十六进制ASCII码
    string res;
    char buff[10];
    for(int i=0;i<input.size();i++)
    {
        sprintf(buff,"%x",toascii(input[i]));
        res+=string(buff);
    }
    
    //2. 将十六进制进一步转化为二进制
    res=__hexToBinary(res);
    return res;
}

/*4.
 *__XOR:对两个等长二进制字符串进行异或运算
 *Param: a--二进制字符串a，b--二进制字符串b
*/
string Pattern::__XOR(string a,string b)
{
    string res;
    for(int i=0;i<a.size();i++)
    {
        res.push_back((a[i]-'0')^(b[i]-'0')+'0');
    }
    return res;
}

/*5.
 *__ECB: 根据明文和密钥进行ECB加密或者解密
 *Param: input--二进制明文或者密文，长度不限； 
 *       key--二进制字符串密钥，若为DES加密则长度为64，若为AES加密则长度为128
 *       vec--二进制偏移向量，若为DES加密则长度为64，若为AES加密则长度为128，在ECB模式中不会使用该参数
 *       crymode--指定分组密码，为"DES"或者"AES"； 
 *       outmode--加密结果输出格式指定，"0x"/"0b"指定十六进制/二进制输出；
 *       encrypt_or_decrypt--指定加密或者解密，true指定加密，false指定解密
 *Return: 明文，密文或者密钥在内存中的二进制形式或者十六进制形式
*/
string Pattern::__ECB(string input, string key, string vec, string crymode, string outmode, bool encrypt_or_decrypt)
{  
    //1. 文本填充：若为DES加密，则将二进制形式的明文/密文填充到长度可以整除以64；若为AES加密，则将二进制形式的明文/密文填充到长度可以整除以128
    int local_len=(crymode=="DES")?64:128;    //单个分组长度
    while(input.size()%local_len!=0)
    {
        input.push_back('0');
    }

    //2. 进行ECB加密或者解密：即对每一个分组分别使用密钥进行加密
    string res;
    int local_sz=input.size()/local_len;      //明文或者密文划分出来的分组数量

    if(crymode=="DES")
    {
        DES des;
        des.key(key,"0b");
        for(int i=0;i<local_sz;i++)
        {
            res+=(encrypt_or_decrypt==true)?des.encrypt(input.substr(i*local_len,local_len),"0b","0b"):des.decrypt(input.substr(i*local_len,local_len),"0b","0b");
        }
    }
    else
    {
        AES aes;
        aes.key(key,"0b");
        for(int i=0;i<local_sz;i++)
        {
            res+=(encrypt_or_decrypt==true)?aes.encrypt(input.substr(i*local_len,local_len),"0b","0b"):aes.decrypt(input.substr(i*local_len,local_len),"0b","0b");
        }
    }

    return (outmode=="0x")?__binToHexto(res):res;
}

/*6.
 *__CBC: 根据明文和密钥进行CBC加密或者解密
 *Param: input--二进制明文或者密文，长度不限； 
 *       key--二进制字符串密钥，若为DES加密则长度为64，若为AES加密则长度为128
 *       vec--二进制偏移向量，若为DES加密则长度为64，若为AES加密则长度为128
 *       crymode--指定分组密码，为"DES"或者"AES"； 
 *       outmode--加密结果输出格式指定，"0x"/"0b"指定十六进制/二进制输出；
 *       encrypt_or_decrypt--指定加密或者解密，true指定加密，false指定解密
 *Return: 明文，密文或者密钥在内存中的二进制形式或者十六进制形式
*/
string Pattern::__CBC(string input, string key, string vec, string crymode, string outmode, bool encrypt_or_decrypt)
{
    //1. 文本填充：若为DES加密，则将二进制形式的明文/密文填充到长度可以整除以64；若为AES加密，则将二进制形式的明文/密文填充到长度可以整除以128
    int local_len=(crymode=="DES")?64:128;    //单个分组长度
    while(input.size()%local_len!=0)
    {
        input.push_back('0');
    }

    //2. 进行CBC加密或者解密：若为加密，则对于每个明文分组，首先先与上一个分组的加密结果进行异或，然后进行加密；若为解密，则对于每个密文分组，首先进行解密，解密结果再与上一个分组的密文进行异或
    string res;              //加密或者解密结果
    int local_sz=input.size()/local_len;    //分组数量
    if(encrypt_or_decrypt)   //加密情况
    {
        if(crymode=="DES")
        {
            DES des=DES();
            des.key(key,"0b");
            //首先加密第一个分组
            res+=des.encrypt(__XOR(input.substr(0,local_len),vec),"0b","0b");     
            //然后加密后续分组
            for(int i=1;i<local_sz;i++)
            {
                res+=des.encrypt(__XOR(input.substr(i*local_len,local_len),res.substr((i-1)*local_len,local_len)),"0b","0b");
            }
        }
        else
        {
            AES aes=AES();
            aes.key(key,"0b");
            //首先加密第一个分组
            res+=aes.encrypt(__XOR(input.substr(0,local_len),vec),"0b","0b");  
            //然后加密后续分组
            for(int i=1;i<local_sz;i++)
            {
                res+=aes.encrypt(__XOR(input.substr(i*local_len,local_len),res.substr((i-1)*local_len,local_len)),"0b","0b");
            }
        }
    }
    else                     //解密情况
    {
        if(crymode=="DES")
        {
            DES des=DES();
            des.key(key,"0b");
            //首先解密第一个分组
            res+=__XOR(des.decrypt(input.substr(0,local_len),"0b","0b"),vec);
            //然后解密后续分组
            for(int i=1;i<local_sz;i++)
            {
                res+=__XOR(des.decrypt(input.substr(i*local_len,local_len),"0b","0b"),input.substr((i-1)*local_len,local_len));
            }
        }
        else
        {
            AES aes=AES();
            aes.key(key,"0b");
            //首先解密第一个分组
            res+=__XOR(aes.decrypt(input.substr(0,local_len),"0b","0b"),vec);
            //然后解密后续分组
            for(int i=1;i<local_sz;i++)
            {
                res+=__XOR(aes.decrypt(input.substr(i*local_len,local_len),"0b","0b"),input.substr((i-1)*local_len,local_len));
            }
        }
    }

    return (outmode=="0x")?__binToHexto(res):res;
}

/*6.
 *__CFB: 根据明文和密钥进行CFB加密或者解密
 *Param: input--二进制明文或者密文，长度不限； 
 *       key--二进制字符串密钥，若为DES加密则长度为64，若为AES加密则长度为128
 *       vec--二进制偏移向量，若为DES加密则长度为64，若为AES加密则长度为128
 *       crymode--指定分组密码，为"DES"或者"AES"； 
 *       outmode--加密结果输出格式指定，"0x"/"0b"指定十六进制/二进制输出；
 *       encrypt_or_decrypt--指定加密或者解密，true指定加密，false指定解密
 *Return: 明文，密文或者密钥在内存中的二进制形式或者十六进制形式
*/
string Pattern::__CFB(string input, string key, string vec, string crymode, string outmode, bool encrypt_or_decrypt)
{
    //1. 首先将明文/密文填充至8的整数倍
	int local_len=8;   //统一的单个加密输出分组长度
    while(input.size()%local_len!=0)
    {
        input.push_back('0');
    }
    int local_sz=input.size()/local_len;     //划分出的分组数量

    //2. 然后根据CFB模式的定义进行CFB加密
    string res;
    if(encrypt_or_decrypt)   //加密情况
    {
        //首先加密第一个分组
        DES des; AES aes;
        if(crymode=="DES") des.key(key,"0b"); else aes.key(key,"0b");
        string tempvec=vec;   //初始向量
        string tempres=(crymode=="DES")?des.encrypt(tempvec,"0b","0b"): aes.encrypt(tempvec,"0b","0b");   //先加密初始向量
        res+=__XOR(tempres.substr(0,local_len),input.substr(0,local_len));                                //然后将加密结果tempres的左侧p位和明文的第一个分组进行异或，得到第一个分组加密的最终结果
        //然后加密后续分组
        for(int i=1;i<local_sz;i++)
        {
            tempvec=tempvec.substr(local_len,tempvec.size()-local_len)+res.substr((i-1)*local_len,local_len);      //更新初始向量：新的初始向量由原先初始向量左移local_len位，然后再与上一次的加密结果拼接而成
            tempres=(crymode=="DES")?des.encrypt(tempvec,"0b","0b"): aes.encrypt(tempvec,"0b","0b");               //加密初始向量
            res+=__XOR(tempres.substr(0,local_len),input.substr(i*local_len,local_len));                           //然后将加密结果tempres的左侧p位和第i个分组进行异或，得到第i个分组加密的最终结果
        }
    }
    else
    {
        //首先解密第一个分组
        DES des; AES aes;
        if(crymode=="DES") des.key(key,"0b"); else aes.key(key,"0b");
        string tempvec=vec;  //初始向量
        string tempres=(crymode=="DES")?des.encrypt(tempvec,"0b","0b"): aes.encrypt(tempvec,"0b","0b");  //先加密初始向量
        res+=__XOR(tempres.substr(0,local_len),input.substr(0,local_len));                               //然后将加密结果tempres的左侧p位和密文的第一个分组进行异或，得到第一个分组加密的最终结果
        //然后加密后续分组
        for(int i=1;i<local_sz;i++)
        {
            tempvec=tempvec.substr(local_len,tempvec.size()-local_len)+input.substr((i-1)*local_len,local_len);    //更新初始向量：新的初始向量由原先初始向量左移local_len位，然后再与上一个密文分组拼接而成
            tempres=(crymode=="DES")?des.encrypt(tempvec,"0b","0b"): aes.encrypt(tempvec,"0b","0b");               //加密初始向量
            res+=__XOR(tempres.substr(0,local_len),input.substr(i*local_len,local_len));                           //然后将加密结果tempres的左侧p位和第i个分组进行异或，得到第i个分组加密的最终结果
        }
    }

    return (outmode=="0x")?__binToHexto(res):res;
}

/*7.
 *__OFB: 根据明文和密钥进行OFB加密或者解密
 *Param: input--二进制明文或者密文，长度不限； 
 *       key--二进制字符串密钥，若为DES加密则长度为64，若为AES加密则长度为128
 *       vec--二进制偏移向量，若为DES加密则长度为64，若为AES加密则长度为128
 *       crymode--指定分组密码，为"DES"或者"AES"； 
 *       outmode--加密结果输出格式指定，"0x"/"0b"指定十六进制/二进制输出；
 *       encrypt_or_decrypt--指定加密或者解密，true指定加密，false指定解密
 *Return: 明文，密文或者密钥在内存中的二进制形式或者十六进制形式
*/
string Pattern::__OFB(string input, string key, string vec, string crymode, string outmode, bool encrypt_or_decrypt)
{
	//1. 文本填充：若为DES加密，则将二进制形式的明文/密文填充到长度可以整除以64；若为AES加密，则将二进制形式的明文/密文填充到长度可以整除以128
    int local_len=(crymode=="DES")?64:128;    //单个分组长度
    while(input.size()%local_len!=0)
    {
        input.push_back('0');
    }
    int local_sz=input.size()/local_len;

    //2. 进行OFB加密或者解密：若为加密，则每一个明文分组与上一次的初始向量的加密结果异或得到最终结果；若为解密，则每一个密文分组与上一次的初始向量的加密结果异或得到最终结果
    string res;
    DES des; AES aes;
    if(crymode=="DES") des.key(key,"0b"); else aes.key(key,"0b");
    
    string tempvec=vec;

    for(int i=0;i<local_sz;i++)
    {
        tempvec=(crymode=="DES")?des.encrypt(tempvec,"0b","0b"):aes.encrypt(tempvec,"0b","0b");
        res+=__XOR(tempvec,input.substr(i*local_len,local_len));
    }

	return (outmode=="0x")?__binToHexto(res):res;
}

/*8.
 *__CTR: 根据明文和密钥进行CTR加密或者解密
 *Param: input--二进制明文或者密文，长度不限； 
 *       key--二进制字符串密钥，若为DES加密则长度为64，若为AES加密则长度为128
 *       vec--二进制偏移向量，若为DES加密则长度为64，若为AES加密则长度为128
 *       crymode--指定分组密码，为"DES"或者"AES"； 
 *       outmode--加密结果输出格式指定，"0x"/"0b"指定十六进制/二进制输出；
 *       encrypt_or_decrypt--指定加密或者解密，true指定加密，false指定解密
 *Return: 明文，密文或者密钥在内存中的二进制形式或者十六进制形式
*/
string Pattern::__CTR(string input, string key, string vec, string crymode, string outmode, bool encrypt_or_decrypt)
{
	//1. 文本填充：若为DES加密，则将二进制形式的明文/密文填充到长度可以整除以64；若为AES加密，则将二进制形式的明文/密文填充到长度可以整除以128
    int local_len=(crymode=="DES")?64:128;    //单个分组长度
    while(input.size()%local_len!=0)
    {
        input.push_back('0');
    }
    int local_sz=input.size()/local_len;

    //2. 进行CTR加密或者解密：若为加密，则每一个明文分组与计数器值的加密结果进行异或得到对应的密文分组；若为解密，则则每一个密文分组与计数器值的加密结果进行异或得到对应的明文分组
    string counter=vec;           //初始向量作为计数器的初始值
    string res;
    DES des; AES aes;
    if(crymode=="DES") des.key(key,"0b"); else aes.key(key,"0b");
    for(int i=0;i<local_sz;i++)
    {
    	//cout<<"counter="<<counter<<endl;
        string tempres=(crymode=="DES")?des.encrypt(counter,"0b","0b"):aes.encrypt(counter,"0b","0b");
        res+=__XOR(tempres,input.substr(i*local_len,local_len));
        counter=__COUNTER(counter);    //获取下一个计数器值（下一个计数器值为当前计数器值加1）
    }

	return (outmode=="0x")?__binToHexto(res):res;
}

/*9.
 *__COUNTER: CTR模式中使用的计数器，获取下一个计数器的值，其中下一个计数器的值即为上一个计数器的值加1 
 *Param: lastcount--长度为64或者128的二进制字符串，上一个计数器的值
 *Return: 长度为64或者128的二进制字符串，下一个计数器的值
*/
string Pattern::__COUNTER(string lastcount)
{
    if(lastcount[lastcount.size()-1]=='0')
    {
    	lastcount[lastcount.size()-1]='1';
    }
    else
    {
    	int index=lastcount.size()-1;
    	while(lastcount[index]=='1'&&index>=0)
    	{
    		lastcount[index]='0';
    		index--;
		}
		lastcount[index]='1';
	}
	return lastcount;
}


