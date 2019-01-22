/*****************************************************************
*Module Name: DES
*Module Date: 2018-11-28
*Module Auth: pzh
*Description: Simple DES module for single DES-64 encrypt
*****************************************************************/

#include <iostream>
#include <string>
#include <cmath>
#include <map>
#include <exception>

using namespace std;

class DES
{
    public:
    DES();                                                            //DES: 默认构造函数
    void key(string key, string mode);                                //key: 设定密钥
    string encrypt(string input, string inmode, string outmode);      //encrypt: DES加密
    string decrypt(string input, string inmode, string outmode);      //decrypt: DES解密
    string getkey(string mode);                                       //getkey:获取当前密钥
    private:

    int __plain[64], __enpt[64], __key[64];           //plain, enpt, key: 最近的明文和密文，密钥
    bool __flag;

    string hexToBinary(string input);                              //hexToBinary: 十六进制输入转换为二进制
    string binToHexto(string input);                               //binToHexto: 二进制输入转换为十六进制
    void ipSub(const int input[64], int output[64]);               //ipSub: IP置换
    void eSub(const int input[32], int output[48]);                //eSub: E扩展置换
    void shiftBinary(int lis[56], int num);                        //shiftBinary: 循环左移
    void keySub(int roll_no, const int input[64],int output[48]);  //keySub: 密钥置换
    void sSub(const int input[48], int output[32]);                //sSub: S盒代替
    void pSub(const int input[32], int output[32]);                //pSub: P盒代替
    void ipReSub(const int input[64], int output[64]);             //ipReSub: IP逆置换
    void roleDES(const int leftinput[32],const int rightinput[32],int leftoutput[32],int rightoutput[32],int rolekey[48]);    //roleDES:单轮DES加密
    void _DES(int input[64],int output[64],int key[64]);           //_DES: 底层DES加密实现
    void _deDES(int input[64],int output[64],int key[64]);         //_deDES: 底层DES解密实现 
};

/********************* public functions *************************/

/*0.
 *DES: 类默认初始化函数
*/
DES::DES()
{
    __flag=false;
}

/*1.
 *key: 该方法设定DES加密密钥
 *Param: input--无前缀十六进制或者二进制输入， mode--'0b'指示二进制输入，'0x'指示十六进制输入
*/
void DES::key(string key, string mode)
{
    __flag=true;
    if(mode=="0x")
    key=hexToBinary(key);
    for(int i=0;i<key.size();i++)
    {
        __key[i]=key[i]-'0';
    }
    return;
}

/*2.
 *encrypt: 该方法进行DES加密，返回加密后的密文
 *Param: input--无前缀十六进制或者二进制明文输入， inmode--'0b'指示以二进制形式输入，'0x'指示以十六进制形式输入，outmode--'0b'指示以二进制形式输出，'0x'指示以十六进制形式输出
 *Return: 无前缀十六进制或者二进制密文输出
*/                  
string DES::encrypt(string input, string inmode, string outmode)
{
    if(!__flag)
    throw "Having not set key for encrypt or decrypt";

    input=(inmode=="0x")?hexToBinary(input):input;
    for(int i=0;i<input.size();i++)
    {
        __plain[i]=input[i]-'0';
    }

    _DES(__plain,__enpt,__key);
    
    string output;
    for(int i=0;i<64;i++)
    {
        output.push_back(__enpt[i]+'0');
    }
    output=(outmode=="0x")?binToHexto(output):output;
    return output;
}

/*3.
 *decrypt: 该方法进行DES解密，返回解密后的明文
 *Param: input--无前缀十六进制或者二进制明文输入， inmode--'0b'指示以二进制形式输入，'0x'指示以十六进制形式输入，outmode--'0b'指示以二进制形式输出，'0x'指示以十六进制形式输出
 *Return: 无前缀十六进制或者二进制明文输出
*/     
string DES::decrypt(string input, string inmode, string outmode)
{
    if(!__flag)
    throw "Having not set key for encrypt or decrypt";

    input=(inmode=="0x")?hexToBinary(input):input;
    for(int i=0;i<input.size();i++)
    {
        __enpt[i]=input[i]-'0';
    }

    _deDES(__enpt,__plain,__key);
    
    string output;
    for(int i=0;i<64;i++)
    {
        output.push_back(__plain[i]+'0');
    }
    output=(outmode=="0x")?binToHexto(output):output;
    return output;
}

/*4.
 *hexToBinary: 该方法将十六进制字符串转化为二进制字符串（均不含前缀） 
 *Param: input--无前缀十六进制输入
 *Return：output--无前缀二进制输出
*/
string DES::getkey(string mode)
{
    string key;
    for(int i=0;i<key.size();i++)
    {
        key.push_back(__key[i]+'0');
    }
    return key;
}


/********************* private functions ************************/

/*1.
 *hexToBinary: 该方法将十六进制字符串转化为二进制字符串（均不含前缀） 
 *Param: input--无前缀十六进制输入
 *Return：output--无前缀二进制输出
*/
string DES::hexToBinary(string input)
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
string DES::binToHexto(string input)
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
 *ipSub: 该方法进行IP置换
 *Param: input--64位长度输入，output--64位长度IP置换结果输出
*/
void DES::ipSub(const int input[64],int output[64])
{
    //首先，制作IP置换表
    int IP_lis[64]={58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7};    //IP置换表
    //然后，进行置换并生成IP置换结果
    for(int i=0;i<64;i++)
    {
        output[i]=input[IP_lis[i]-1];
    }
    return;
}

/*4.
 *eSub:该方法进行E扩展置换
 *Param: input--32位长度输入，output--48位长度E扩展置换输出
*/
void DES::eSub(const int input[32],int output[48])
{
    //首先，制作E扩展置换表
    int E_lis[48]={32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1};
    //然后，进行置换并生成E扩展置换结果
    for(int i=0;i<48;i++)
    {
        output[i]=input[E_lis[i]-1];
    }
    return;
}

/*5.
 *shiftBinary:该方法对输入的二进制数组进行前后半段的分别进行循环左移操作
 *参数列表:lis--56位二进制数组，num--循环左移位数
*/
void DES::shiftBinary(int lis[56],int num)
{
    int temp2[56];
    for(int i=0;i<28;i++)
    {
        temp2[i]=lis[(i+num)%28];
    }
    for(int i=28;i<56;i++)
    {
        temp2[i]=lis[(i-28+num)%28+28];
    }
    for(int i=0;i<56;i++)
    {
        lis[i]=temp2[i];
    }
    return;
}

/*6.
 *keySub: 该方法进行密钥置换
 *Param: roll_no--当前加密轮数(0-15)，input--64位原始密钥输入，output--48位当前轮加密密钥输出
*/
void DES::keySub(int roll_no,const int input[64],int output[48])
{
    //首先，制作从64位到56位的密钥置换表，56位到48位输出的密钥置换表，和各个加密轮数的移位表
    int roll_lis[16]={1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};    //各个轮数的移位位数表
    int lis_64_56[56]={57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4};    //64位到56位的置换表
    int lis_56_48[48]={14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32};    //56位到48位输出的置换表
    //然后，先对原始输入密钥input进行从64位到56位的置换(PC-1置换)
    int temp[56];
    for(int i=0;i<56;i++)
    {
        temp[i]=input[lis_64_56[i]-1];
    }
    //然后对该PC-1置换的56位结果进行前后半段的分别移位，注意当前是多少轮就需要迭代移位多少次
    for(int i=0;i<roll_no;i++)
    {
        shiftBinary(temp,roll_lis[i]);
    }
    //然后对上述移位结果作从56位到48位的PC-2置换，即可得到最终的48位当前轮密钥
    for(int i=0;i<48;i++)
    {
        output[i]=temp[lis_56_48[i]-1];
    }
    return;
}

/*7.
 *sSub: 该方法进行S盒代替
 *Param: input--48位E扩展置换结果和当前轮48位密钥的48位异或结果，output--32位S盒代替结果
*/
void DES::sSub(const int input[48],int output[32])
{
    //首先制作8个DES加密标准S盒
    int S_Box[8][4][16]={                     //8个S盒三维数组
    // S1
    14, 4,  13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
    0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
    4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
    15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,
    // S2
    15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
    3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
    0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
    13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,
    // S3
    10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
    13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
    13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
    1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,
    // S4
    7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
    13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
    10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
    3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,
    // S5
    2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
    14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
    4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
    11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3,
    // S6
    12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
    10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
    9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
    4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13,
    // S7
    4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
    13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
    1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
    6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,
    // S8
    13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
    1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
    7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
    2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
    };
    //然后，依次使用S盒对48位输入数据进行代替处理
    for(int i=0;i<8;i++)    //每一个S盒处理6个输入数据的位
    {
        //当前S盒处理的6位数据中，最高位和最低位组成行数，中间四位作为列数
        //最高位为i*6+5，最低位为i*6，中间四位分别为i*6+1,i*6+2,i*6+3,i*6+4
        int row=input[i*6]*2+input[i*6+5]*1;     //计算S盒输出值所在行数
        int col=input[i*6+1]*8+input[i*6+2]*4+input[i*6+3]*2+input[i*6+4]*1;   //计算S盒输出值所在列数
        int res=S_Box[i][row][col];     //输出值（十进制）     
        //最后将十进制转化为二进制并写入输出output的对应位置
        for(int k=3;k>=0;k--)
        {
            output[i*4+k]=res%2;
            res/=2;
        }
    }
    return;
}

/*8.
 *pSub: 该方法进行P盒置换
 *Param: input--32位S盒代替后的结果输入，output--32位P盒置换结果输出
*/
void DES::pSub(const int input[32],int output[32])
{
    //首先制作P盒
    int P_box[32]={16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
    //然后使用P盒对32位输入进行P盒置换，得到32位输出
    for(int i=0;i<32;i++)
    {
        output[i]=input[P_box[i]-1];
    }
    return;
}

/*9.
 *ipReSub: 该方法进行IP逆置换
 *Param: input--32位输入，output--32位IP逆置换结果输出
*/
void DES::ipReSub(const int input[64],int output[64])
{
    //首先生成IP置换表
    int REIP_lis[64]={40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25};
    //然后根据IP逆置换表进行IP逆置换
    for(int i=0;i<64;i++)
    {
        output[i]=input[REIP_lis[i]-1];
    }
    return;
}

/*10.
 *roleDES: 该方法进行单轮DES加密
 *Param: leftinput--32位左半部分原文输入，rightinput--32位右半部分原文输入，leftoutput--32位左半部分原文输出，rightoutput--32位右半部分原文输出，key--当前轮的48位密钥
*/
void DES::roleDES(const int leftinput[32],const int rightinput[32],int leftoutput[32],int rightoutput[32],int rolekey[48])
{
    //首先计算左半部分输出，左半部分输出就是右半部分输入
    for(int i=0;i<32;i++)
    {
        leftoutput[i]=rightinput[i];
    }
    //然后计算右半部分输出，这部分按照如下几个步骤完成
    //1.对原始的32位右半部分输入作E扩展置换，扩展为48位
    int rightinput_2[48];
    eSub(rightinput,rightinput_2);
    //2.将48位的E扩展置换结果rightinput_2与当前轮的密钥进行异或操作
    int rightinput_3[48];
    for(int i=0;i<48;i++)
    {
        rightinput_3[i]=rightinput_2[i]^rolekey[i];
    }
    //3.将异或结果依次进行S盒代替以及P盒置换
    int rightinput_4[32];
    sSub(rightinput_3,rightinput_4);     //问题在此 
    int rightinput_5[32];
    pSub(rightinput_4,rightinput_5);
    //4.将两轮代替以及置换后的结果再和左半部分输入leftinput进行异或操作
    int rightinput_6[32];
    for(int i=0;i<32;i++)
    {
        rightinput_6[i]=rightinput_5[i]^leftinput[i];
    }
    //5.rightinput_6就是最终的右半部分输出结果
    for(int i=0;i<32;i++)
    {
        rightoutput[i]=rightinput_6[i];
    }
}

/*11.
 *DES:该方法进行DES加密
 *Param:input--64位明文输入，output--64位密文输出，key--64位DES加密原始密钥（其中56位有效，其余位数作为奇偶校验位）
*/
void DES::_DES(int input[64],int output[64],int key[64])
{
    //1.将原始明文进行IP置换
    int input_2[64];
    ipSub(input,input_2);
    //2.将原始明文分拆为左右两部分，进行16轮的DES单轮加密，最后再将得到的左右两部分合并
    int leftinput[32],rightinput[32],leftoutput[32],rightoutput[32],rolekey[48];
    for(int i=0;i<64;i++)
    {
        if(i>=0&&i<32)
        leftinput[i]=input_2[i];
        else
        rightinput[i-32]=input_2[i];
    }
    for(int i=1;i<=16;i++)
    {
        //首先生成当前轮的密钥
        keySub(i,key,rolekey);
        //利用当前轮密钥进行加密
        roleDES(leftinput,rightinput,leftoutput,rightoutput,rolekey); 
        //然后令leftinput=leftoutput,rightinput=rightoutput，准备进行下一轮迭代
        for(int i=0;i<32;i++)
        {
            leftinput[i]=leftoutput[i];
            rightinput[i]=rightoutput[i];
        }
    }
    //最后一轮得到的leftoutput和rightoutput即为得到的密文
    //3.对得到的两个32位密文互换位置后合并，然后进行IP逆置换，即得到最终加密的密文结果output
    int tempres[64];
    for(int i=0;i<64;i++)
    {
        if(i>=0&&i<32)
        tempres[i]=rightoutput[i];
        else
        tempres[i]=leftoutput[i-32];
    }
    ipReSub(tempres,output);
    return;
}

/*12.
 *deDES: 该方法进行DES解密
 *Param: input--64位密文输入，output--64位明文输出，key--64位DES加密原始密钥
*/
void DES::_deDES(int input[64],int output[64],int key[64])
{
    //1.将原始明文进行IP置换
    int input_2[64];
    ipSub(input,input_2);
    //2.将原始明文分拆为左右两部分，进行16轮的DES单轮加密，最后再将得到的左右两部分合并
    int leftinput[32],rightinput[32],leftoutput[32],rightoutput[32],rolekey[48];
    for(int i=0;i<64;i++)
    {
        if(i>=0&&i<32)
        leftinput[i]=input_2[i];
        else
        rightinput[i-32]=input_2[i];
    }
    for(int i=16;i>=1;i--)
    {
        //首先生成当前轮的密钥
        keySub(i,key,rolekey);    //DES解密时需要反向使用密钥
        //利用当前轮密钥进行加密
        roleDES(leftinput,rightinput,leftoutput,rightoutput,rolekey);       
        //然后令leftinput=leftoutput,rightinput=rightoutput，准备进行下一轮迭代
        for(int i=0;i<32;i++)
        {
            leftinput[i]=leftoutput[i];
            rightinput[i]=rightoutput[i];
        }
    }
    //最后一轮得到的leftoutput和rightoutput即为得到的密文
    //3.对得到的两个32位密文互换位置后合并，然后进行IP逆置换，即得到最终加密的密文结果output
    int tempres[64];
    for(int i=0;i<64;i++)
    {
        if(i>=0&&i<32)
        tempres[i]=rightoutput[i];
        else
        tempres[i]=leftoutput[i-32];
    }
    ipReSub(tempres,output);
    return;
}
