/*****************************************************************
*Module Name: MD5
*Module Date: 2018-11-28
*Module Auth: pzh
*Description: Simple MD5 module for single MD5 hashing
*****************************************************************/

#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <map>
#include <cstdlib>
#include <cstring>
#include <cstdio>

using namespace std;

class MD5
{
    public:
    MD5();                                                            //DES: 默认构造函数
    string hash(string input, string inmode, string outmode);      //hash: 进行MD5 Hash，返回MD5 Hash结果
    private:

    unsigned int __plain, __enpt;                                  //__plain: 原始消息; __enpt: MD5 Hash结果

    string hexToBinary(string input);                              //hexToBinary: 十六进制输入转换为二进制
    string binToHexto(string input);                               //binToHexto: 二进制输入转换为十六进制
    void print(unsigned int input);                                //print: 将unsigned int类型以32位二进制的形式输出
    string convert(unsigned int input);                            //convert: 将unsigned int类型以32位二进制的形式字符串转化
    string fillString(string input);                               //fillString: 对原始输入的二进制序列进行填充，填充到长度size符合size%512==448，然后附加一个64位的填充前长度值序列
    void initDepart(string input,vector<string> &output);          //initDepart: 该方法将N*512位的二进制字符串拆分为若干512位的字符串数组
    void departString(string input,unsigned int output[16]);       //departString: 将512位的二进制序列输入拆分为16个32位二进制的unsigned int类型x序列
    unsigned int cycleLeftShift(unsigned int a,unsigned int b);    //cycleLeftShift: 实现循环左移
    unsigned int F(unsigned int x,unsigned int y,unsigned int z);  //F: 非线性函数F
    unsigned int G(unsigned int x,unsigned int y,unsigned int z);  //G: 非线性函数G
    unsigned int H(unsigned int x,unsigned int y,unsigned int z);  //H: 非线性函数H
    unsigned int I(unsigned int x,unsigned int y,unsigned int z);  //I: 非线性函数I
    unsigned int FF(unsigned int &a,unsigned int b,unsigned int c ,unsigned int d ,unsigned int Mj,unsigned int s,unsigned int ti);  //FF: 复合操作函数FF
    unsigned int GG(unsigned int &a,unsigned int b,unsigned int c ,unsigned int d ,unsigned int Mj,unsigned int s,unsigned int ti);  //GG: 复合操作函数GG
    unsigned int HH(unsigned int &a,unsigned int b,unsigned int c ,unsigned int d ,unsigned int Mj,unsigned int s,unsigned int ti);  //HH: 复合操作函数HH
    unsigned int II(unsigned int &a,unsigned int b,unsigned int c ,unsigned int d ,unsigned int Mj,unsigned int s,unsigned int ti);  //HH: 复合操作函数II
    string _MD5(string user_input);                                //_MD5:MD5 Hash底层实现函数
};

/********************* public functions *************************/

/*0.
 *MD5: 类默认初始化函数
*/
MD5::MD5()
{
}

/*2.
 *hash: 该方法进行MD5 Hash，返回MD5 Hash结果
 *Param: input--无前缀十六进制或者二进制原始信息输入， inmode--'0b'指示以二进制形式输入，'0x'指示以十六进制形式输入，outmode--'0b'指示以二进制形式输出，'0x'指示以十六进制形式输出
 *Return: 无前缀十六进制或者二进制Hash结果输出
*/                  
string MD5::hash(string input, string inmode, string outmode)
{
    input=(inmode=="0x")?hexToBinary(input):input;
    string res=_MD5(input);
    res=(outmode=="0x")?binToHexto(res):res;

    return res;
}


/********************* private functions ************************/

/*1.
 *hexToBinary: 该方法将十六进制字符串转化为二进制字符串（均不含前缀） 
 *Param: input--无前缀十六进制输入
 *Return：output--无前缀二进制输出
*/
string MD5::hexToBinary(string input)
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
string MD5::binToHexto(string input)
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
 *print: 该方法将unsigned int类型以32位二进制的形式输出
 *Param: input--需要输出的unsigned int类型数字
*/
void MD5::print(unsigned int input)
{
    //这里使用的算法非常经典，通过不断移位来输出每一个二进制位，需要特别注意该种方法，移位的执行效率是非常之高的
    for(int i=31;i>=0;i--)
    {
        cout<<((input>>i)&1);
    }
}

/*4.
 *convert: 该方法将unsigned int类型以32位二进制的形式字符串转化
 *Param: input--需要输出的unsigned int类型数字
*/
string MD5::convert(unsigned int input)
{
    //这里使用的算法非常经典，通过不断移位来输出每一个二进制位，需要特别注意该种方法，移位的执行效率是非常之高的
    string res;
    for(int i=31;i>=0;i--)
    {
        res.push_back(((input>>i)&1)+'0');
    }
    return res;
}

/*5.
 *fillString: 该方法对原始输入的二进制序列进行填充，填充到长度size符合size%512==448，然后附加一个64位的填充前长度值序列
 *Param: input--输入二进制序列。返回值:string类型--填充后的二进制序列
*/
string MD5::fillString(string input)
{
    //1.首先判断是否需要进行填充，需要填充的情况下进行填充
    int osize=input.size();
    if(osize%512!=448)
    {
        //1.1对于需要填充的情况，第一次填充1，后续每一次填充0，迭代操作直到长度size符合要求为止
        input.push_back('1');
        while(input.size()%512!=448)
        {
            input.push_back('0');
        }
    }
    //2.在符合条件的序列后添加一个64位二进制序列表示输入二进制序列在填充前的长度值
    string nums="0000000000000000000000000000000000000000000000000000000000000000";
    //2.1首先将原输入字符串长度转化为16进制字符串
    char temp_str[10000];
    sprintf(temp_str,"%x",osize);
    string temp(temp_str);
    temp=hexToBinary(temp_str);
    for(int i=0;i<temp.size();i++)
    {
        nums[i]=temp[i];
    }
    input+=nums;
    return input;
}

/*6.
 *initDepart: 该方法将N*512位的二进制字符串拆分为若干512位的字符串数组
 *Param: input--输入N*512长度的二进制序列字符串输入，output--N个长度为512的二进制序列字符串
*/
void MD5::initDepart(string input,vector<string> &output)
{
    int size=(input.size()+1)/512;
    for(int i=0;i<size;i++)
    {
        string temp;
        for(int k=i*512;k<(i+1)*512;k++)
        {
            temp.push_back(input[k]);
        }
        output.push_back(temp);
    }
    return;
}

/*7.
 *departString: 该方法将512位的二进制序列输入拆分为16个32位二进制的unsigned int类型x序列
 *Param: input--512位输入二进制序列，output--16个32位输出二进制序列
 *Comment: 需要特别注意，在分拆时需要特别注意大端和小端的问题，为了方便，首先对字符串作变换，然后再将字符串转化为unsigned int类型
*/
void MD5::departString(string input,unsigned int output[16])
{
    for(int i=0;i<16;i++)
    {
        string temp;
        //首先将字符串作倒装变换
        for(int k=3;k>=0;k--)
        {
            for(int m=0;m<8;m++)
            {
                temp.push_back(input[i*32+k*8+m]);
            }
        }
        //然后将字符串转化为unsigned int类型
        output[i]=strtoul(temp.c_str(),0,2);     //string转unsigned int常使用内置strtoul来进行快速实现，当然也可以自行实现 
    }
    return;
}

/*8.
 *cycleLeftShift: 实现循环左移
 *Param: a--待移位数，b--移位数
 *Return: 移位结果
*/
unsigned int MD5::cycleLeftShift(unsigned int a,unsigned int b)
{
    unsigned int res=a<<b;    //先将a进行左移b位得到结果1
    res|=a>>(32-b);       //再将a进行右移32-b位得到a的前b位，即结果2，最后再将结果1和结果2进行或操作进行合并
    return res;
}

/*9.
 *4个非线性函数F,G,H,I的实现
*/
//非线性函数F
unsigned int MD5::F(unsigned int x,unsigned int y,unsigned int z)
{
    return (x&y)|((~x)&z);
}

//非线性函数G
unsigned int MD5::G(unsigned int x,unsigned int y,unsigned int z)
{
    return (x&z)|(y&(~z));
}

//非线性函数H
unsigned int MD5::H(unsigned int x,unsigned int y,unsigned int z)
{
    return x^y^z;
}

//非线性函数I
unsigned int MD5::I(unsigned int x,unsigned int y,unsigned int z)
{
    return y^(x|(~z));
}

/*10.
 *4个复合操作函数FF,GG,HH,II的实现
 *Comment: 需要特别注意，MD5使用复合操作函数的过程中，会改变各个参数的值后作为下一次使用复合函数的输入，因此输入参数a需要使用引用形式，且其中的移位为循环左移位
*/
//复合操作函数FF
unsigned int MD5::FF(unsigned int &a,unsigned int b,unsigned int c ,unsigned int d ,unsigned int Mj,unsigned int s,unsigned int ti)
{
    a = b + cycleLeftShift( (a + F(b,c,d) + Mj + ti), s);
}

//复合操作函数GG
unsigned int MD5::GG(unsigned int &a,unsigned int b,unsigned int c ,unsigned int d ,unsigned int Mj,unsigned int s,unsigned int ti)
{
    a = b + cycleLeftShift( (a + G(b,c,d) + Mj + ti), s);
}

//复合操作函数HH
unsigned int MD5::HH(unsigned int &a,unsigned int b,unsigned int c ,unsigned int d ,unsigned int Mj,unsigned int s,unsigned int ti)
{
    a = b + cycleLeftShift( (a + H(b,c,d) + Mj + ti), s);
}

//复合操作函数II
unsigned int MD5::II(unsigned int &a,unsigned int b,unsigned int c ,unsigned int d ,unsigned int Mj,unsigned int s,unsigned int ti)
{
    a = b + cycleLeftShift( (a + I(b,c,d) + Mj + ti), s);
}

/*11.
 *MD5: 该方法用户输入字符串进行MD5核心算法
 *Param: user_input--用户字符串输入
 *Return: 128位MD5算法结果输出
 *Comment: 本处需要严格注意MD5加密过程中所需要使用的参数值
*/
string MD5::_MD5(string user_input)
{
    //MD-5加密参量
    unsigned int x[16]={};
	unsigned int A=0x67452301;
	unsigned int B=0xefcdab89;
	unsigned int C=0x98badcfe;
	unsigned int D=0x10325476;    
    //首先将用户输入的字符串进行填充，并以512为一组进行分组
    user_input=fillString(user_input);
    vector<string> lis;
    initDepart(user_input,lis);
    //cout<<user_input<<endl;

    //对每个512位的分组，先拆分为16个32位的子分组，然后对每个分组进行四轮循环复合操作
    for(int i=0;i<lis.size();i++)
    {
    	unsigned int a=A;
    	unsigned int b=B;
    	unsigned int c=C;
    	unsigned int d=D;
    	
        unsigned int input[16];
        departString(lis[i],input);
        //cout<<binToHexto(lis[i])<<endl;

        //第一轮循环:16次复合操作
        FF(a ,b ,c ,d ,input[0] ,7 ,0xd76aa478 );
        FF(d ,a ,b ,c ,input[1] ,12 ,0xe8c7b756 );
        FF(c ,d ,a ,b ,input[2] ,17 ,0x242070db );
        FF(b ,c ,d ,a ,input[3] ,22 ,0xc1bdceee );
        FF(a ,b ,c ,d ,input[4] ,7 ,0xf57c0faf );
        FF(d ,a ,b ,c ,input[5] ,12 ,0x4787c62a );
        FF(c ,d ,a ,b ,input[6] ,17 ,0xa8304613 );
        FF(b ,c ,d ,a ,input[7] ,22 ,0xfd469501);
        FF(a ,b ,c ,d ,input[8] ,7 ,0x698098d8 );
        FF(d ,a ,b ,c ,input[9] ,12 ,0x8b44f7af );
        FF(c ,d ,a ,b ,input[10] ,17 ,0xffff5bb1 );
        FF(b ,c ,d ,a ,input[11] ,22 ,0x895cd7be );
        FF(a ,b ,c ,d ,input[12] ,7 ,0x6b901122 );
        FF(d ,a ,b ,c ,input[13] ,12 ,0xfd987193 );
        FF(c ,d ,a ,b ,input[14] ,17 ,0xa679438e );
        FF(b ,c ,d ,a ,input[15] ,22 ,0x49b40821 );

        //第二轮循环:16次复合操作
        GG(a ,b ,c ,d ,input[1] ,5 ,0xf61e2562 );
        GG(d ,a ,b ,c ,input[6] ,9 ,0xc040b340 );
        GG(c ,d ,a ,b ,input[11] ,14 ,0x265e5a51);
        GG(b ,c ,d ,a ,input[0] ,20 ,0xe9b6c7aa );
        GG(a ,b ,c ,d ,input[5] ,5 ,0xd62f105d );
        GG(d ,a ,b ,c ,input[10] ,9 ,0x02441453 );
        GG(c ,d ,a ,b ,input[15] ,14 ,0xd8a1e681 );
        GG(b ,c ,d ,a ,input[4] ,20 ,0xe7d3fbc8 );
        GG(a ,b ,c ,d ,input[9] ,5 ,0x21e1cde6 );
        GG(d ,a ,b ,c ,input[14] ,9 ,0xc33707d6 );
        GG(c ,d ,a ,b ,input[3] ,14 ,0xf4d50d87 );
        GG(b ,c ,d ,a ,input[8] ,20 ,0x455a14ed );
        GG(a ,b ,c ,d ,input[13] ,5 ,0xa9e3e905 );
        GG(d ,a ,b ,c ,input[2] ,9 ,0xfcefa3f8 );
        GG(c ,d ,a ,b ,input[7] ,14 ,0x676f02d9 );
        GG(b ,c ,d ,a ,input[12] ,20 ,0x8d2a4c8a );

        //第三轮循环:16次复合操作
        HH(a ,b ,c ,d ,input[5] ,4 ,0xfffa3942 );
        HH(d ,a ,b ,c ,input[8] ,11 ,0x8771f681 );
        HH(c ,d ,a ,b ,input[11] ,16 ,0x6d9d6122 );
        HH(b ,c ,d ,a ,input[14] ,23 ,0xfde5380c );
        HH(a ,b ,c ,d ,input[1] ,4 ,0xa4beea44 );
        HH(d ,a ,b ,c ,input[4] ,11 ,0x4bdecfa9 );
        HH(c ,d ,a ,b ,input[7] ,16 ,0xf6bb4b60 );
        HH(b ,c ,d ,a ,input[10] ,23 ,0xbebfbc70 );
        HH(a ,b ,c ,d ,input[13] ,4 ,0x289b7ec6 );
        HH(d ,a ,b ,c ,input[0] ,11 ,0xeaa127fa );
        HH(c ,d ,a ,b ,input[3] ,16 ,0xd4ef3085 );
        HH(b ,c ,d ,a ,input[6] ,23 ,0x04881d05 );
        HH(a ,b ,c ,d ,input[9] ,4 ,0xd9d4d039 );
        HH(d ,a ,b ,c ,input[12] ,11 ,0xe6db99e5 );
        HH(c ,d ,a ,b ,input[15] ,16 ,0x1fa27cf8 );
        HH(b ,c ,d ,a ,input[2] ,23 ,0xc4ac5665 );

        //第四轮循环:16次复合操作
        II(a ,b ,c ,d ,input[0] ,6 ,0xf4292244 );
        II(d ,a ,b ,c ,input[7] ,10 ,0x432aff97 );
        II(c ,d ,a ,b ,input[14] ,15 ,0xab9423a7);
        II(b ,c ,d ,a ,input[5] ,21 ,0xfc93a039 );
        II(a ,b ,c ,d ,input[12] ,6 ,0x655b59c3 );
        II(d ,a ,b ,c ,input[3] ,10 ,0x8f0ccc92 );
        II(c ,d ,a ,b ,input[10] ,15 ,0xffeff47d );
        II(b ,c ,d ,a ,input[1] ,21 ,0x85845dd1 );
        II(a ,b ,c ,d ,input[8] ,6 ,0x6fa87e4f );
        II(d ,a ,b ,c ,input[15] ,10 ,0xfe2ce6e0 );
        II(c ,d ,a ,b ,input[6] ,15 ,0xa3014314 );
        II(b ,c ,d ,a ,input[13] ,21 ,0x4e0811a1 );
        II(a ,b ,c ,d ,input[4] ,6 ,0xf7537e82 );
        II(d ,a ,b ,c ,input[11] ,10 ,0xbd3af235 );
        II(c ,d ,a ,b ,input[2] ,15 ,0x2ad7d2bb );
        II(b ,c ,d ,a ,input[9] ,21 ,0xeb86d391 );

        //四轮循环后，将a,b,c,d分别加上初始值A,B,C,D，进入下一轮循环
        A+=a;
        B+=b;
        C+=c;
        D+=d;
    }
    
    //最后，将a，b，c，d作拼接即可得到最终MD5算法运行结果
    //附注:拼接时需要特别注意，要按照内存里的存储顺序存储a，b，c，d，首先将a，b，c，d作倒序，然后再进行连接
    
    /*
    cout<<binToHexto(convert(a))<<endl;
    cout<<binToHexto(convert(b))<<endl;
    cout<<binToHexto(convert(c))<<endl;
    cout<<binToHexto(convert(d))<<endl;
    */

    string user_output;
    for(int k=0;k<4;k++)
    {
        for(int m=7;m>=0;m--)
        {
            user_output.push_back(((A>>(k*8+m))&1)+'0');
        }
    }
    for(int k=0;k<4;k++)
    {
        for(int m=7;m>=0;m--)
        {
            user_output.push_back(((B>>(k*8+m))&1)+'0');
        }
    }
    for(int k=0;k<4;k++)
    {
        for(int m=7;m>=0;m--)
        {
            user_output.push_back(((C>>(k*8+m))&1)+'0');
        }
    }
    for(int k=0;k<4;k++)
    {
        for(int m=7;m>=0;m--)
        {
            user_output.push_back(((D>>(k*8+m))&1)+'0');
        }
    }
    return user_output;
}