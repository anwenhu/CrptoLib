#include "SHA512.h"
#include "MD5.h"

using namespace std;

class HashCenter
{
    public:
    //public functions
    HashCenter(string hashmode);
    void reset(string hashmode);
    string gethash(string infor, string outmode);

    private:
    //private functions
    string __convert(string input);
    string __hexToBinary(string input);

    //private variables
    MD5 __md5; SHA512 __sha512;
    string __hashmode;
};

/************************** public functions ***************************/
/*1.
 *HashCenter: HashCenter类的默认构造函数
 *Param: hashmode--指定hash函数，其值为"SHA512"或者"MD5"
 *Return: None
*/
HashCenter::HashCenter(string hashmode)
{
    __hashmode=hashmode;
}

/*2.
 *reset: 重新指定hash函数
 *Param: hashmode--新的指定hash函数种类，其值为"SHA512"或者"MD5"
 *Return: None
*/
void HashCenter::reset(string hashmode)
{
    __hashmode=hashmode;
}

/*3.
 *gethash: 获取输入的原始消息的hash值
 *Param: infor--需要计算hash值的原始消息；outmode--输出格式，"0x"指定hash结果以十六进制格式输出，"0b"指定hash结果以二进制格式输出
 *Return: 原始消息的hash值
*/
string HashCenter::gethash(string infor, string outmode)
{
    infor=__convert(infor);
    if(__hashmode=="MD5")
    return __md5.hash(infor,"0b",outmode);
    else
    return __sha512.hash(infor,"0b",outmode);
}

/************************** private functions **************************/

/*1.
 *__convert: 将用户输入的字符串转化为在内存中的二进制形式
 *Param: input--用户输入的，字符串形式的明文，密文或者密钥
 *Return: 明文，密文或者密钥在内存中的二进制形式
*/
string HashCenter::__convert(string input)
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

/*2.
 *hexToBinary: 该方法将十六进制字符串转化为二进制字符串（均不含前缀） 
 *Param: input--无前缀十六进制输入
 *Return：output--无前缀二进制输出
*/
string HashCenter::__hexToBinary(string input)
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