/*****************************************************************
*Module Name: DAA
*Module Date: 2018-12-03
*Module Auth: pzh
*AEScription: Simple DAA module for get DAA Mac
*****************************************************************/

#include "DES.h"

using namespace std;

class DAA
{
    public:
    string getDac(string input,string key,string inmode,string outmode);//DAA: 该方法实现基于分组密码DES的MAC——DAA数据认证算法
    
    private:
    string hexToBinary(string input);                                   //hexToBinary: 十六进制输入转换为二进制
    string binToHexto(string input);                                    //binToHexto: 二进制输入转换为十六进制
    string XOR(string a,string b);                                      //XOR: 对两个等长二进制字符串进行异或运算
};


/********************* public functions *************************/

/*1.
 *getDac: 该方法实现基于分组密码DES的MAC——DAA数据认证算法
 *Param: input--输入16位十六进制原始消息，key--输入16位十六进制原始密钥，长度需要调用者进行判断
 *Return: output--十六进制DAA消息提取结果
*/
string DAA::getDac(string input,string key,string inmode,string outmode)
{
    //1. 将十六进制的原始消息和密钥转化为二进制形式
    input=(inmode=="0x")?hexToBinary(input):input;
    key=(inmode=="0x")?hexToBinary(key):key;

    //2. 判断当前的原始消息长度是否为64的整数倍，若不是则首先将原始消息使用0在右侧填充至长度为64的整数倍
    while(input.size()%64!=0)
    {
        input.push_back('0');
    }
    
    //3. 将填充后的消息以64位作为一个分组进行划分
    int partsize=input.size()/64;
    string inputlis[partsize];
    for(int i=0;i<partsize;i++)
    {
        for(int k=0;k<64;k++)
        {
            inputlis[i].push_back(input[i*64+k]);
        }
    }

    //4. 将各个分组使用DES的CBC模式进行加密
    DES des=DES();
    des.key(key,"0b");
    string tempres=des.encrypt(inputlis[0],"0b","0b");
    for(int i=1;i<partsize;i++)
    {
        tempres=XOR(tempres,inputlis[i]);
        tempres=des.encrypt(tempres,"0b","0b");
    }

    //5. 最后得到的64位加密结果就是最终的数据认证码DAC
    tempres=(outmode=="0x")?binToHexto(tempres):tempres;

    return tempres;
}


/********************* private functions ************************/

/*1.
 *hexToBinary: 该方法将十六进制字符串转化为二进制字符串（均不含前缀） 
 *Param: input--无前缀十六进制输入
 *Return：output--无前缀二进制输出
*/
string DAA::hexToBinary(string input)
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
string DAA::binToHexto(string input)
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
string DAA::XOR(string a,string b)
{
    string res;
    for(int i=0;i<a.size();i++)
    {
        res.push_back((a[i]-'0')^(b[i]-'0')+'0');
    }
    return res;
}
