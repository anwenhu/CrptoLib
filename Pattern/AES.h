/*****************************************************************
*Module Name: AES
*Module Date: 2018-11-28
*Module Auth: pzh
*AEScription: Simple AES module for single AES-64 encrypt
*****************************************************************/

#include <iostream>
#include <string>
#include <cmath>
#include <map>
#include <exception>
#include <cstdlib> 
#include <cstring>

using namespace std;

struct uint_8
{
    //数据部分
    bool *data=NULL;
    //方法部分
    uint_8();                                   //默认构造函数
    uint_8(string str);                         //初始化构造函数，利用一个输入的8位二进制字符串进行构造
    uint_8(const uint_8 &other);                //拷贝构造函数
    uint_8 &operator = (const uint_8 &other);   //拷贝构造运算符
    ~uint_8();                                  //析构函数
    friend uint_8 operator ^ (const uint_8 &a,const uint_8 &b);    //异或运算符 
};

uint_8::uint_8()    //默认构造函数
{
    data=(bool *)malloc(8*sizeof(bool));
    memset(data,0,8*sizeof(bool));
}

uint_8::uint_8(string str)     //初始化构造函数，利用一个输入的十六进制字符串进行构造
{
    data=(bool *)malloc(8*sizeof(bool));
    map<char,string> dic;      //十六进制数到二进制数的转换表
    dic['0']="0000"; dic['1']="0001"; dic['2']="0010"; dic['3']="0011"; dic['4']="0100"; dic['5']="0101"; dic['6']="0110"; dic['7']="0111"; dic['8']="1000"; dic['9']="1001"; dic['A']="1010"; dic['B']="1011"; dic['C']="1100"; dic['D']="1101"; dic['E']="1110"; dic['F']="1111";dic['a']="1010"; dic['b']="1011"; dic['c']="1100"; dic['d']="1101"; dic['e']="1110"; dic['f']="1111";
    for(int i=0;i<4;i++)
    {
        data[i]=dic[str[2]][i]-'0';
    }
    for(int i=4;i<8;i++)
    {
        data[i]=dic[str[3]][i-4]-'0';     //注意下标变换时需要极度小心，比如此处的i-4
    }
}

uint_8::uint_8(const uint_8 &other)     //拷贝构造函数
{
    //拷贝构造函数无需重新释放内存，只需要申请内存
    data=(bool *)malloc(8*sizeof(bool));
    for(int i=0;i<8;i++)
    {
        data[i]=other.data[i];
    }
}

uint_8 & uint_8::operator = (const uint_8 &other)   //拷贝构造运算符，也可以使用字符串进行设置该变量的值，例如:lis[0][1]=uint_8();
{
    //每个uini_8类型的底层数据结构相同，均为8位，因此无需重新释放和申请内存
    for(int i=0;i<8;i++)
    {
        data[i]=other.data[i];
    }
    return *this;
}

uint_8::~uint_8()                                  //析构函数
{
    free(data);
}

void print(uint_8 a)
{
	for(int i=0;i<8;i++)
	{
		cout<<a.data[i];
	}
}

uint_8 operator ^ (const uint_8 &a,const uint_8 &b)     //位异或运算，二元运算符应该声明在类外作为友元函数
{
    uint_8 res;
    for(int i=0;i<8;i++)
    {
        res.data[i]=a.data[i]^b.data[i];
    }
    return res;
}


class AES
{
    public:
    AES();                                                            //AES: 默认构造函数
    void key(string key, string mode);                                //key: 设定密钥
    string encrypt(string input, string inmode, string outmode);      //encrypt: AES加密
    string decrypt(string input, string inmode, string outmode);      //decrypt: AES解密
    string getkey(string mode);                                       //getkey:获取当前密钥
    private:

    uint_8 __plain[4][4], __enpt[4][4], __key[4][4];                   //plain, enpt, key: 最近的明文和密文，密钥
    string __str_key;                                                  //__str_key: 十六进制原始密钥
    bool __flag;

    string hexToBinary(string input);                                  //hexToBinary: 十六进制输入转换为二进制
    string binToHexto(string input);                                   //binToHexto: 二进制输入转换为十六进制
    void byteExchange(const uint_8 input[4][4],uint_8 output[4][4]);   //byteExchage: 该方法实现字节代换操作
    void deByteExchange(const uint_8 input[4][4],uint_8 output[4][4]); //deByteExchage: 该方法实现逆字节代换操作
    void rowShift(const uint_8 input[4][4],uint_8 output[4][4]);       //rowShift: 该方法实现行移位操作
    void deRowShift(const uint_8 input[4][4],uint_8 output[4][4]);     //deRowShift: 该方法实现逆行移位操作
    uint_8 gfMulti_2(uint_8 input,int exp);                            //gfMulti_2: 该方法计算输入值和2的幂的GF(2^8)有限域乘法结果
    uint_8 gfMulti(uint_8 a,uint_8 b);                                 //gfMulti: 该方法计算输入值和任意值之间的GF(2^8)有限域乘法结果
    void colMix(const uint_8 input[4][4],uint_8 output[4][4]);         //colMix: 该方法实现列混合操作
    void deColMix(const uint_8 input[4][4],uint_8 output[4][4]);       //deColMix: 该方法实现逆列混合操作
    void keyPlus(const uint_8 input[4][4],const uint_8 rolekey[4][4],uint_8 output[4][4]);    //keyPlus: 该方法实现轮密钥加操作，其逆操作就是本身
    void tTransform(const uint_8 input[4],uint_8 output[4],int col);                          //tTransform: 该方法实现密钥生成过程中的T变换
    void keyExtend(const uint_8 input[4][4],uint_8 output[44][4]);                            //keyExtend:该方法实现密钥扩展操作
    void _AES(const uint_8 input[4][4],const uint_8 key[4][4],uint_8 output[4][4]);      //AES: 该方法对输入的4*4字节信息使用给定的4*4字节密钥进行AES加密
    void _deAES(const uint_8 input[4][4],const uint_8 key[4][4],uint_8 output[4][4]);    //deAES: 该方法对输入的4*4字节信息使用给定的4*4字节密钥进行AES解密
};

/********************* public functions *************************/

/*0.
 *AES: 类默认初始化函数
*/
AES::AES()
{
    __flag=false;
}

/*1.
 *key: 该方法设定AES加密密钥
 *Param: input--无前缀十六进制或者二进制输入， mode--'0b'指示二进制输入，'0x'指示十六进制输入
*/
void AES::key(string key, string mode)
{
    __flag=true;

    //按照我们实现的密钥生成算法，密钥矩阵需要按行输入
    key=(mode=="0b")?binToHexto(key):key;
    __str_key=key;
    int m=0;
    for(int i=0;i<4;i++)
    {
        for(int k=0;k<4;k++)
        {
            string temp;
            temp.push_back(key[m]);
            temp.push_back(key[m+1]);
            temp="0x"+temp;
            __key[i][k]=uint_8(temp);
            m+=2;
        }
    }
}

/*2.
 *encrypt: 该方法进行AES加密，返回加密后的密文
 *Param: input--无前缀十六进制或者二进制明文输入， inmode--'0b'指示以二进制形式输入，'0x'指示以十六进制形式输入，outmode--'0b'指示以二进制形式输出，'0x'指示以十六进制形式输出
 *Return: 无前缀十六进制或者二进制密文输出
*/                  
string AES::encrypt(string input, string inmode, string outmode)
{
    if(!__flag)
    throw "Having not set key for encrypt or decrypt";

    //按照我们实现的几个操作算法，明文矩阵需要按列输入
    input=(inmode=="0b")?binToHexto(input):input;
    int m=0;
    for(int i=0;i<4;i++)
    {
        for(int k=0;k<4;k++)
        {
            string temp;
            temp.push_back(input[m]);
            temp.push_back(input[m+1]);
            temp="0x"+temp;
            __plain[k][i]=uint_8(temp);
            m+=2;
        }
    }
    
    _AES(__plain,__key,__enpt);

    string res;
    map<string,string> dic;
    dic["0000"]="0"; dic["0001"]="1"; dic["0010"]="2"; dic["0011"]="3"; dic["0100"]="4"; dic["0101"]="5"; dic["0110"]="6"; dic["0111"]="7"; dic["1000"]="8"; dic["1001"]="9"; dic["1010"]="a"; dic["1011"]="b"; dic["1100"]="c"; dic["1101"]="d"; dic["1110"]="e"; dic["1111"]="f";
    for(int i=0;i<4;i++)
    {
        for(int k=0;k<4;k++)
        {
            string x1=to_string(__enpt[k][i].data[0])+to_string(__enpt[k][i].data[1])+to_string(__enpt[k][i].data[2])+to_string(__enpt[k][i].data[3]);
            string x2=to_string(__enpt[k][i].data[4])+to_string(__enpt[k][i].data[5])+to_string(__enpt[k][i].data[6])+to_string(__enpt[k][i].data[7]);
            res+=(dic[x1]+dic[x2]);
        }
    }
    res=(outmode=="0b")?hexToBinary(res):res;
    
    return res;
}

/*3.
 *decrypt: 该方法进行AES解密，返回解密后的明文
 *Param: input--无前缀十六进制或者二进制明文输入， inmode--'0b'指示以二进制形式输入，'0x'指示以十六进制形式输入，outmode--'0b'指示以二进制形式输出，'0x'指示以十六进制形式输出
 *Return: 无前缀十六进制或者二进制明文输出
*/     
string AES::decrypt(string input, string inmode, string outmode)
{
    if(!__flag)
    throw "Having not set key for encrypt or decrypt";

    //按照我们实现的几个操作算法，明文矩阵需要按列输入
    input=(inmode=="0b")?binToHexto(input):input;
    int m=0;
    for(int i=0;i<4;i++)
    {
        for(int k=0;k<4;k++)
        {
            string temp;
            temp.push_back(input[m]);
            temp.push_back(input[m+1]);
            temp="0x"+temp;
            __enpt[k][i]=uint_8(temp);
            m+=2;
        }
    }
    
    _deAES(__enpt,__key,__plain);

    string res;
    map<string,string> dic;
    dic["0000"]="0"; dic["0001"]="1"; dic["0010"]="2"; dic["0011"]="3"; dic["0100"]="4"; dic["0101"]="5"; dic["0110"]="6"; dic["0111"]="7"; dic["1000"]="8"; dic["1001"]="9"; dic["1010"]="a"; dic["1011"]="b"; dic["1100"]="c"; dic["1101"]="d"; dic["1110"]="e"; dic["1111"]="f";
    for(int i=0;i<4;i++)
    {
        for(int k=0;k<4;k++)
        {
            string x1=to_string(__plain[k][i].data[0])+to_string(__plain[k][i].data[1])+to_string(__plain[k][i].data[2])+to_string(__plain[k][i].data[3]);
            string x2=to_string(__plain[k][i].data[4])+to_string(__plain[k][i].data[5])+to_string(__plain[k][i].data[6])+to_string(__plain[k][i].data[7]);
            res+=(dic[x1]+dic[x2]);
        }
    }
    res=(outmode=="0b")?hexToBinary(res):res;
    
    return res;
}

/*4.
 *getkey: 该方法获取AES加密类的当前密钥
 *Param: mode--'0b'指示以二进制形式输出，'0x'指示以十六进制形式输出
 *Return：output--二进制或十六进制AES密钥
*/
string AES::getkey(string mode)
{
	string res=(mode=="0b")?hexToBinary(__str_key):__str_key;
    return res;
}


/********************* private functions ************************/

/*1.
 *hexToBinary: 该方法将十六进制字符串转化为二进制字符串（均不含前缀） 
 *Param: input--无前缀十六进制输入
 *Return：output--无前缀二进制输出
*/
string AES::hexToBinary(string input)
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
string AES::binToHexto(string input)
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

//用于字节代换操作的S盒
static const string S[16][16] = { "0x63", "0x7c", "0x77", "0x7b", "0xf2", "0x6b", "0x6f", "0xc5", "0x30", "0x01", "0x67", "0x2b", "0xfe", "0xd7", "0xab", "0x76",
"0xca", "0x82", "0xc9", "0x7d", "0xfa", "0x59", "0x47", "0xf0", "0xad", "0xd4", "0xa2", "0xaf", "0x9c", "0xa4", "0x72", "0xc0",
"0xb7", "0xfd", "0x93", "0x26", "0x36", "0x3f", "0xf7", "0xcc", "0x34", "0xa5", "0xe5", "0xf1", "0x71", "0xd8", "0x31", "0x15",
"0x04", "0xc7", "0x23", "0xc3", "0x18", "0x96", "0x05", "0x9a", "0x07", "0x12", "0x80", "0xe2", "0xeb", "0x27", "0xb2", "0x75",
"0x09", "0x83", "0x2c", "0x1a", "0x1b", "0x6e", "0x5a", "0xa0", "0x52", "0x3b", "0xd6", "0xb3", "0x29", "0xe3", "0x2f", "0x84",
"0x53", "0xd1", "0x00", "0xed", "0x20", "0xfc", "0xb1", "0x5b", "0x6a", "0xcb", "0xbe", "0x39", "0x4a", "0x4c", "0x58", "0xcf",
"0xd0", "0xef", "0xaa", "0xfb", "0x43", "0x4d", "0x33", "0x85", "0x45", "0xf9", "0x02", "0x7f", "0x50", "0x3c", "0x9f", "0xa8",
"0x51", "0xa3", "0x40", "0x8f", "0x92", "0x9d", "0x38", "0xf5", "0xbc", "0xb6", "0xda", "0x21", "0x10", "0xff", "0xf3", "0xd2",
"0xcd", "0x0c", "0x13", "0xec", "0x5f", "0x97", "0x44", "0x17", "0xc4", "0xa7", "0x7e", "0x3d", "0x64", "0x5d", "0x19", "0x73",
"0x60", "0x81", "0x4f", "0xdc", "0x22", "0x2a", "0x90", "0x88", "0x46", "0xee", "0xb8", "0x14", "0xde", "0x5e", "0x0b", "0xdb",
"0xe0", "0x32", "0x3a", "0x0a", "0x49", "0x06", "0x24", "0x5c", "0xc2", "0xd3", "0xac", "0x62", "0x91", "0x95", "0xe4", "0x79",
"0xe7", "0xc8", "0x37", "0x6d", "0x8d", "0xd5", "0x4e", "0xa9", "0x6c", "0x56", "0xf4", "0xea", "0x65", "0x7a", "0xae", "0x08",
"0xba", "0x78", "0x25", "0x2e", "0x1c", "0xa6", "0xb4", "0xc6", "0xe8", "0xdd", "0x74", "0x1f", "0x4b", "0xbd", "0x8b", "0x8a",
"0x70", "0x3e", "0xb5", "0x66", "0x48", "0x03", "0xf6", "0x0e", "0x61", "0x35", "0x57", "0xb9", "0x86", "0xc1", "0x1d", "0x9e",
"0xe1", "0xf8", "0x98", "0x11", "0x69", "0xd9", "0x8e", "0x94", "0x9b", "0x1e", "0x87", "0xe9", "0xce", "0x55", "0x28", "0xdf",
"0x8c", "0xa1", "0x89", "0x0d", "0xbf", "0xe6", "0x42", "0x68", "0x41", "0x99", "0x2d", "0x0f", "0xb0", "0x54", "0xbb", "0x16" };

//用于逆字节代换操作的S2盒
static const string S2[16][16] = { "0x52", "0x09", "0x6a", "0xd5", "0x30", "0x36", "0xa5", "0x38", "0xbf", "0x40", "0xa3", "0x9e", "0x81", "0xf3", "0xd7", "0xfb",
"0x7c", "0xe3", "0x39", "0x82", "0x9b", "0x2f", "0xff", "0x87", "0x34", "0x8e", "0x43", "0x44", "0xc4", "0xde", "0xe9", "0xcb",
"0x54", "0x7b", "0x94", "0x32", "0xa6", "0xc2", "0x23", "0x3d", "0xee", "0x4c", "0x95", "0x0b", "0x42", "0xfa", "0xc3", "0x4e",
"0x08", "0x2e", "0xa1", "0x66", "0x28", "0xd9", "0x24", "0xb2", "0x76", "0x5b", "0xa2", "0x49", "0x6d", "0x8b", "0xd1", "0x25",
"0x72", "0xf8", "0xf6", "0x64", "0x86", "0x68", "0x98", "0x16", "0xd4", "0xa4", "0x5c", "0xcc", "0x5d", "0x65", "0xb6", "0x92",
"0x6c", "0x70", "0x48", "0x50", "0xfd", "0xed", "0xb9", "0xda", "0x5e", "0x15", "0x46", "0x57", "0xa7", "0x8d", "0x9d", "0x84",
"0x90", "0xd8", "0xab", "0x00", "0x8c", "0xbc", "0xd3", "0x0a", "0xf7", "0xe4", "0x58", "0x05", "0xb8", "0xb3", "0x45", "0x06",
"0xd0", "0x2c", "0x1e", "0x8f", "0xca", "0x3f", "0x0f", "0x02", "0xc1", "0xaf", "0xbd", "0x03", "0x01", "0x13", "0x8a", "0x6b",
"0x3a", "0x91", "0x11", "0x41", "0x4f", "0x67", "0xdc", "0xea", "0x97", "0xf2", "0xcf", "0xce", "0xf0", "0xb4", "0xe6", "0x73",
"0x96", "0xac", "0x74", "0x22", "0xe7", "0xad", "0x35", "0x85", "0xe2", "0xf9", "0x37", "0xe8", "0x1c", "0x75", "0xdf", "0x6e",
"0x47", "0xf1", "0x1a", "0x71", "0x1d", "0x29", "0xc5", "0x89", "0x6f", "0xb7", "0x62", "0x0e", "0xaa", "0x18", "0xbe", "0x1b",
"0xfc", "0x56", "0x3e", "0x4b", "0xc6", "0xd2", "0x79", "0x20", "0x9a", "0xdb", "0xc0", "0xfe", "0x78", "0xcd", "0x5a", "0xf4",
"0x1f", "0xdd", "0xa8", "0x33", "0x88", "0x07", "0xc7", "0x31", "0xb1", "0x12", "0x10", "0x59", "0x27", "0x80", "0xec", "0x5f",
"0x60", "0x51", "0x7f", "0xa9", "0x19", "0xb5", "0x4a", "0x0d", "0x2d", "0xe5", "0x7a", "0x9f", "0x93", "0xc9", "0x9c", "0xef",
"0xa0", "0xe0", "0x3b", "0x4d", "0xae", "0x2a", "0xf5", "0xb0", "0xc8", "0xeb", "0xbb", "0x3c", "0x83", "0x53", "0x99", "0x61",
"0x17", "0x2b", "0x04", "0x7e", "0xba", "0x77", "0xd6", "0x26", "0xe1", "0x69", "0x14", "0x63", "0x55", "0x21", "0x0c", "0x7d" };

/*3.
 *byteExchage: 该方法实现字节代换操作
 *Param: input--4*4状态矩阵输入，output--4*4状态矩阵输出
*/
void AES::byteExchange(const uint_8 input[4][4],uint_8 output[4][4])
{
    //进行字节代换操作
    for(int i=0;i<4;i++)
    {
        for(int k=0;k<4;k++)
        {
            int row=input[i][k].data[0]*8+input[i][k].data[1]*4+input[i][k].data[2]*2+input[i][k].data[3]*1;   //将输入的状态矩阵的元素的前4位作为行数
            int col=input[i][k].data[4]*8+input[i][k].data[5]*4+input[i][k].data[6]*2+input[i][k].data[7]*1;   //将输入的状态矩阵的元素的后4位作为列数
            output[i][k]=uint_8(S[row][col]);       //将原元素替换为S盒中处于对应行和列的元素
        }
    }
    return;
}

/*4.
 *deByteExchage: 该方法实现逆字节代换操作
 *Param: input--4*4状态矩阵输入，output--4*4状态矩阵输出
*/
void AES::deByteExchange(const uint_8 input[4][4],uint_8 output[4][4])
{
    //进行逆字节代换操作
    for(int i=0;i<4;i++)
    {
        for(int k=0;k<4;k++)
        {
            int row=input[i][k].data[0]*8+input[i][k].data[1]*4+input[i][k].data[2]*2+input[i][k].data[3]*1;   //将输入的状态矩阵的元素的前4位作为行数
            int col=input[i][k].data[4]*8+input[i][k].data[5]*4+input[i][k].data[6]*2+input[i][k].data[7]*1;   //将输入的状态矩阵的元素的后4位作为列数
            output[i][k]=uint_8(S2[row][col]);       //将原元素替换为S盒中处于对应行和列的元素
        }
    }
    return;
}

/*5.
 *rowShift: 该方法实现行移位操作
 *Param: input--4*4状态矩阵输入，output--4*4状态矩阵输出
*/
void AES::rowShift(const uint_8 input[4][4],uint_8 output[4][4])
{
    //行移位操作的具体细节是：对于AES-128的4*4输入状态矩阵，将其第i行的元素循环左移i位
    for(int i=0;i<4;i++)
    {
        for(int k=0;k<4;k++)
        {
            output[i][k]=input[i][(k+i)%4];
        }
    }
    return;
}

/*6.
 *deRowShift: 该方法实现逆行移位操作
 *Param: input--4*4状态矩阵输入，output--4*4状态矩阵输出
*/
void AES::deRowShift(const uint_8 input[4][4],uint_8 output[4][4])
{
    //逆行移位操作的具体细节是：对于AES-128的4*4输入状态矩阵，将其第i行的元素循环右移i位
    for(int i=0;i<4;i++)
    {
        for(int k=0;k<4;k++)
        {
            output[i][k]=input[i][(k-i+4)%4];
        }
    }
    return;
}

/*7.
 *gfMulti_2: 该方法计算输入值和2的幂的GF(2^8)有限域乘法结果
 *Param: exp--2的幂的指数，input--输入值
 *Return：输入值和2的幂的GF(2^8)有限域乘法结果
*/
uint_8 AES::gfMulti_2(uint_8 input,int exp)
{
    if(exp==0)
    return input;
    else 
    {
        for(int k=0;k<exp;k++)
        {
        	bool first=input.data[0];    //在移位操作之前的输入数值的首位
        	//首先将输入左移一位，且右侧补0
        	for(int i=0;i<7;i++)
        	{
            	input.data[i]=input.data[i+1];
        	}
        	input.data[7]=0;
        	//然后判断移位前的输入数值的首位是否为0，若为0，则直接返回移位结果；若为1，则将移位结果与二进制数00011011异或后再返回
        	input=(first==0)?input:(input^uint_8("0x1B"));
		}
		return input;
    }
}

/*8.
 *gfMulti: 该方法计算输入值和任意值之间的GF(2^8)有限域乘法结果
 *Param: a--有限域乘法乘数1，b--有限域乘法乘数2
*/
uint_8 AES::gfMulti(uint_8 a,uint_8 b)
{
    //我们将输入b进行分解，然后遍历输入b的每一个二进制位，若二进制位b.data[i]为1，则将结果异或gfMulti_2(a,8-i-1)
    uint_8 res;
    for(int i=0;i<8;i++)
    {
        if(b.data[i]==1)
        {
            res=res^gfMulti_2(a,8-i-1);   
        }
    }
    return res;
}

/*9.
 *colMix: 该方法实现列混合操作
 *Param: input--4*4状态矩阵输入，output--4*4状态矩阵输出
*/
void AES::colMix(const uint_8 input[4][4],uint_8 output[4][4])
{
    //直接使用实验中推导的有限域算术公式进行计算列混合
    for(int i=0;i<4;i++)
    {
        output[0][i]=gfMulti(input[0][i],uint_8("0x02"))^gfMulti(input[1][i],uint_8("0x03"))^input[2][i]^input[3][i];
        output[1][i]=input[0][i]^gfMulti(input[1][i],uint_8("0x02"))^gfMulti(input[2][i],uint_8("0x03"))^input[3][i];
        output[2][i]=input[0][i]^input[1][i]^gfMulti(input[2][i],uint_8("0x02"))^gfMulti(input[3][i],uint_8("0x03"));
        output[3][i]=gfMulti(input[0][i],uint_8("0x03"))^input[1][i]^input[2][i]^gfMulti(input[3][i],uint_8("0x02"));
    }
    return;
}

/*10.
 *deColMix: 该方法实现逆列混合操作
 *Param: input--4*4状态矩阵输入，output--4*4状态矩阵输出
*/
void AES::deColMix(const uint_8 input[4][4],uint_8 output[4][4])
{
    //直接使用实验中推导的有限域算术公式进行计算逆列混合
    for(int i=0;i<4;i++)
    {
        output[0][i]=gfMulti(input[0][i],uint_8("0x0E"))^gfMulti(input[1][i],uint_8("0x0B"))^gfMulti(input[2][i],uint_8("0x0D"))^gfMulti(input[3][i],uint_8("0x09"));
        output[1][i]=gfMulti(input[0][i],uint_8("0x09"))^gfMulti(input[1][i],uint_8("0x0E"))^gfMulti(input[2][i],uint_8("0x0B"))^gfMulti(input[3][i],uint_8("0x0D"));
        output[2][i]=gfMulti(input[0][i],uint_8("0x0D"))^gfMulti(input[1][i],uint_8("0x09"))^gfMulti(input[2][i],uint_8("0x0E"))^gfMulti(input[3][i],uint_8("0x0B"));
        output[3][i]=gfMulti(input[0][i],uint_8("0x0B"))^gfMulti(input[1][i],uint_8("0x0D"))^gfMulti(input[2][i],uint_8("0x09"))^gfMulti(input[3][i],uint_8("0x0E"));
    }
    return;
}

/*11.
 *keyPlus: 该方法实现轮密钥加操作，其逆操作就是本身
 *Param: input--4*4状态矩阵输入，rolekey--4*4二进制数轮密钥输入，output--4*4状态矩阵输出
 *notes: 为了存储结构的连续性，keyExtend方法生成的每一轮所用的子密钥Wi是按照行排列的，因此在进行轮密钥加时，需要先将该函数生成的子函数作转置
*/
void AES::keyPlus(const uint_8 input[4][4],const uint_8 rolekey[4][4],uint_8 output[4][4])
{
    for(int i=0;i<4;i++)
    {
        for(int k=0;k<4;k++)
        {
            output[i][k]=input[i][k]^rolekey[k][i];    //与子密钥的转置进行轮密钥加操作  
        }
    }
    return;
}

/*12.
 *tTransform: 该方法实现密钥生成过程中的T变换
 *Param: input--输入4位密钥内容，output--输出4位密钥内容，col--当前列数
*/
void AES::tTransform(const uint_8 input[4],uint_8 output[4],int col)
{
    //1.首先对输入的4位密钥内容进行字循环操作，将输入内容循环左移一个字节
    for(int i=0;i<4;i++)
    {
        output[i]=input[(i+1)%4];
    }
    //2.然后使用S盒进行密钥的字节代换
    for(int k=0;k<4;k++)
    {
        int row=output[k].data[0]*8+output[k].data[1]*4+output[k].data[2]*2+output[k].data[3]*1;   //将输入的状态矩阵的元素的前4位作为行数
        int col=output[k].data[4]*8+output[k].data[5]*4+output[k].data[6]*2+output[k].data[7]*1;   //将输入的状态矩阵的元素的后4位作为列数
        output[k]=uint_8(S[row][col]);       //将原元素替换为S盒中处于对应行和列的元素
    }
    //3.最后进行轮常量异或操作
    static string role_S[10][4]={"0x01","0x00","0x00","0x00",
    "0x02","0x00","0x00","0x00",
    "0x04","0x00","0x00","0x00",
    "0x08","0x00","0x00","0x00",
    "0x10","0x00","0x00","0x00",
    "0x20","0x00","0x00","0x00",
    "0x40","0x00","0x00","0x00",
    "0x80","0x00","0x00","0x00",
    "0x1B","0x00","0x00","0x00",
    "0x36","0x00","0x00","0x00"};
    int target=col/4-1;
    for(int i=0;i<4;i++)
    {
        output[i]=output[i]^role_S[target][i];
    }
    return;
}

/*13.
 *keyExtend: 该方法实现密钥扩展操作
 *Param: input--4*4个uint_8类型元素组成的初始输入密钥(w[0],w[1],w[2],w[3]按行格式输入)，output--4*44个uint_8类型组成的各轮密钥，总共4列44行，每一轮加密使用其中的4行
 *notes: 为了存储结构的连续性，本处生成的每一轮所用的子密钥Wi是按照行排列的，因此在进行轮密钥加时，需要先将该函数生成的子函数作转置
*/
void AES::keyExtend(const uint_8 input[4][4],uint_8 output[44][4])
{
    //首先，输出的前4行和输入的前4列相同
    for(int i=0;i<4;i++)
    {
        for(int k=0;k<4;k++)
        {
            output[i][k]=input[i][k];
        }
    }
    //然后，为输出的各轮密钥扩展40行，因此总计44行
    //扩展的行的生成方法是：若生成的第i行（从0开始）的行数i不是4的倍数，则第i行密钥由第i-1行和第i-4行异或而得到；而若生成的第i行的行数i是4的倍数，则第i行密钥通过第i-4行的密钥，以及第i-1行的密钥经过T变换后的结果异或而得到
    for(int i=4;i<44;i++)
    {
        if(i%4!=0)      
        {
            for(int k=0;k<4;k++)
            {
                output[i][k]=output[i-1][k]^output[i-4][k];
            }
        }
        else
        {
            uint_8 t_res[4];
            tTransform(output[i-1],t_res,i);         //T变换
            for(int k=0;k<4;k++)
            {
                output[i][k]=t_res[k]^output[i-4][k];
            }   
        }
    }
    return;
}

/*14.
 *_AES: 该方法对输入的4*4字节信息使用给定的4*4字节密钥进行AES加密
*/
void AES::_AES(const uint_8 input[4][4],const uint_8 key[4][4],uint_8 output[4][4])
{
    //本处严格按照如下几个步骤来实现给定信息的AES加密
    //1.根据初始密钥key计算各轮密钥rolekey
    uint_8 rolekey[44][4];
    keyExtend(key,rolekey);
    //2.使用第一组密钥rolekey[0:3]进行轮密钥加操作
    uint_8 output_0[4][4];
    keyPlus(input,rolekey,output_0);
    //3.循环执行9轮加密操作，一轮加密操作中包含的过程为:字节代换-行移位-列混合-轮密钥加
    for(int i=0;i<9;i++)
    {
        //3.1.进行字节代换
        uint_8 output_1[4][4];
        byteExchange(output_0,output_1);
        //3.2.进行行移位
        uint_8 output_2[4][4];
        rowShift(output_1,output_2);
        //3.3.进行列混合
        uint_8 output_3[4][4];
        colMix(output_2,output_3);
        //3.4.进行轮密钥加
        //进行轮密钥加时，必须严格确定所使用的是rolekey中的第几组密钥，
        keyPlus(output_3,rolekey+(i+1)*4,output_0);     //注意这里的指针操作，二维数组指针的精细操作请参见C++相关教材
    }
    //4.进行第10轮加密，第10轮包含的过程为:字节代换-行移位-轮密钥加，不包含列混合
    //4.1.进行字节代换
    uint_8 output_1[4][4];
    byteExchange(output_0,output_1);
    //4.2.进行行移位
    uint_8 output_2[4][4];
    rowShift(output_1,output_2);
    //4.3.进行轮密钥加
    keyPlus(output_2,rolekey+40,output);   //output即为最终结果输出参数
    return;
}

/*15.
 *_deAES:该方法对输入的4*4字节信息使用给定的4*4字节密钥进行AES解密
*/
void AES::_deAES(const uint_8 input[4][4],const uint_8 key[4][4],uint_8 output[4][4])
{
    //本处严格使用如下几个步骤来实现AES解密
    //1.根据初始密钥计算各轮解密密钥
    uint_8 rolekey[44][4];
    keyExtend(key,rolekey);
    //2.使用最后一组密钥进行轮密钥加
    uint_8 output_0[4][4];
    keyPlus(input,rolekey+40,output_0);
    //3.循环进行9轮解密操作，每轮解密操作包括如下几个子步骤:逆行移位-逆字节代换-轮密钥加-逆列混合
    for(int i=8;i>=0;i--)
    {
        //3.1.进行逆行移位操作
        uint_8 output_1[4][4];
        deRowShift(output_0,output_1);
        //3.2.进行逆字节代换操作
        uint_8 output_2[4][4];
        deByteExchange(output_1,output_2);
        //3.3.进行轮密钥加操作
        uint_8 output_3[4][4];
        keyPlus(output_2,rolekey+(i+1)*4,output_3);
        //3.4.进行逆列混合操作
        deColMix(output_3,output_0);
    }
    //4.最后一轮解密操作仅包含三个步骤，即:逆行移位-逆字节代换-轮密钥加
    uint_8 output_1[4][4];
    deRowShift(output_0,output_1);
    uint_8 output_2[4][4];
    deByteExchange(output_1,output_2);
    keyPlus(output_2,rolekey,output);
    return;
}