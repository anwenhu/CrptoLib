/*****************************************************************
*Module Name: HMAC(SHA512)
*Module Date: 2018-12-01
*Module Auth: pzh
*Description: Simple HMAC module using SHA-512 hashing
*****************************************************************/

#include "SHA512.h"
#include "MD5.h"
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <map>
#include <cstdlib>
#include <cstring>
#include <cstdio>

using namespace std;

class HMAC
{
    public:
    string getMac(string input,string key,string mode,string informat,string outformat);    //getMac: 获得基于SHA-512或者MD5 Hash函数的HMAC消息认证码
    
    private:
    string hexToBinary(string input);                              //hexToBinary: 十六进制输入转换为二进制
    string binToHexto(string input);                               //binToHexto: 二进制输入转换为十六进制
    string XOR(string a,string b);                                 //XOR:对两个等长二进制字符串进行异或运算
};



/********************* public functions *************************/

/*1.
 *getMac: 使用SHA-512 Hash函数实现的HMAC消息认证码
 *Param: input--原始十六进制消息输入，output--原始十六进制密钥输入
 *Return: output--十六进制HMAC消息认证码
*/
string HMAC::getMac(string input,string key,string mode,string informat,string outformat)
{
    SHA512 sha512;
    MD5 md5;

    //1.将输入的原始信息input和原始密钥key由十六进制序列转化为二进制序列
    input=(informat=="0x")?hexToBinary(input):input;
    key=(informat=="0x")?hexToBinary(key):key;

    //2.密钥长度变换:
    //若原始密钥key长度大于SHA-512分组长度1024位，则将key作为输入送入SHA-512 Hash算法，得到的512位Hash结果再在左侧进行添0，得到的1024位结果作为新的密钥值；若原始密钥key的长度小于1024，则直接在右侧（教材有误）进行添0，得到的1024结果作为新的密钥值
    if(key.size()>1024)
    key=(mode=="sha512")?sha512.hash(key,"0b","0b"):md5.hash(key,"0b","0b");
    string fill(1024-key.size(),'0');  
    key=key+fill;

    //3.生成1024位常量ipad,opad
    string ipad,opad;
    for(int i=0;i<1024/8;i++)
    {
        ipad+="00110110";
        opad+="01011100";
    }

    //4.计算tempres=H[(K^ipad)||M]
    string tempres=XOR(key,ipad)+input;
    tempres=(mode=="sha512")?sha512.hash(tempres,"0b","0b"):md5.hash(tempres,"0b","0b");

    //5.计算res=H[(K^opad)||tempres]，res即为最终的SHA-512 HMAC消息认证码
    string res=XOR(key,opad)+tempres;
    res=(mode=="sha512")?sha512.hash(res,"0b","0b"):md5.hash(res,"0b","0b");
    res=(outformat=="0x")?binToHexto(res):res;
    
    return res;
}



/********************* private functions ************************/

/*1.
 *hexToBinary: 该方法将十六进制字符串转化为二进制字符串（均不含前缀） 
 *Param: input--无前缀十六进制输入
 *Return：output--无前缀二进制输出
*/
string HMAC::hexToBinary(string input)
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
 *binToHexto: 该方法将十六进制字符串转化为二进制字符串（均不含前缀）
 *Param: input--无前缀二进制输入
 *Return: output--无前缀十六进制输出
*/
string HMAC::binToHexto(string input)
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
 *XOR:对两个等长二进制字符串进行异或运算
 *Param: a--二进制字符串a，b--二进制字符串b
*/
string HMAC::XOR(string a,string b)
{
    string res;
    for(int i=0;i<a.size();i++)
    {
        res.push_back((a[i]-'0')^(b[i]-'0')+'0');
    }
    return res;
}
