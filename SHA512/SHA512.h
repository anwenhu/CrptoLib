#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <map>
#include <cstdlib>
#include <cstring>
#include <cstdio>

using namespace std;

class SHA512
{
    public:
    SHA512();                                                      //SHA512: 默认构造函数
    string hash(string input, string inmode, string outmode);      //hash: 进行SHA512 Hash，返回SHA512 Hash结果
    private:

    unsigned int __plain, __enpt;                                  //__plain: 原始消息; __enpt: SHA512 Hash结果

    string hexToBinary(string input);                              //hexToBinary: 十六进制输入转换为二进制
    string binToHexto(string input);                               //binToHexto: 二进制输入转换为十六进制
    void print(unsigned long long int input);                                //print: 将unsigned int类型以32位二进制的形式输出
    string convert(unsigned long long int input);                            //convert: 将unsigned int类型以32位二进制的形式字符串转化
    string fillString(string input);                               //fillString: 该方法对原始输入的二进制序列进行填充                     

    void initDepart(string input,vector<string> &output);          //initDepart: 该方法将N*1024位的二进制字符串拆分为若干1024位的字符串数组

    // SHA-512在轮函数F中使用的4个复合操作函数 
    unsigned long long int cycleRightShift(unsigned long long int a,unsigned long long int b);                //cycleRightShift:实现循环右移
    unsigned long long int Ch(unsigned long long int e,unsigned long long int f,unsigned long long int g);    //Ch: 复合操作函数Ch
    unsigned long long int Maj(unsigned long long int a,unsigned long long int b,unsigned long long int c);   //Maj: 复合操作函数Maj
    unsigned long long int Sigma0(unsigned long long int a);       //Sigma0: 复合操作函数Sigma0
    unsigned long long int Sigma1(unsigned long long int e);       //Sigma1: 复合操作函数Sigma1

    void F(unsigned long long int &a,unsigned long long int &b,unsigned long long int &c,unsigned long long int &d,unsigned long long int &e,unsigned long long int &f,unsigned long long int &g,unsigned long long int &h,unsigned long long int Wi,unsigned long long int Ki);   //F: SHA-512的单轮函数F
    
    // SHA-512的在消息扩展中所使用的2个复合操作函数
    unsigned long long int Theta0(unsigned long long int x);       //Theta0: 复合操作函数Theta0
    unsigned long long int Theta1(unsigned long long int x);       //Theta1: 复合操作函数Theta1

    void FExtended(string input,unsigned long long int output[80]);//FExtended:该方法为轮函数进行消息扩展操作
    string _SHA512(string input);                                  //_SHA512: SHA-512 Hash算法底层实现方法
};


/**********************************public functions********************************************/

/*0.
 *SHA512: 类默认初始化函数
*/
SHA512::SHA512()
{
}

/*2.
 *hash: 该方法进行SHA512 Hash，返回SHA512 Hash结果
 *Param: input--无前缀十六进制或者二进制原始信息输入， inmode--'0b'指示以二进制形式输入，'0x'指示以十六进制形式输入，outmode--'0b'指示以二进制形式输出，'0x'指示以十六进制形式输出
 *Return: 无前缀十六进制或者二进制Hash结果输出
*/                  
string SHA512::hash(string input, string inmode, string outmode)
{
    input=(inmode=="0b")?binToHexto(input):input;
    string res=_SHA512(input);
    res=(outmode=="0b")?hexToBinary(res):res;
    
    return res;
}


/**********************************private functions*******************************************/

/*1.
 *hexToBinary: 该方法将十六进制字符串转化为二进制字符串（均不含前缀）
 *Param: input--无前缀十六进制输入
 *Return: output--无前缀二进制输出
*/
string SHA512::hexToBinary(string input)
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
string SHA512::binToHexto(string input)
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
 *print: 该方法将unsigned long long int类型以64位二进制的形式输出
 *Param: input--需要输出的unsigned long long int类型数字
*/
void SHA512::print(unsigned long long int input)
{
    //这里使用的算法非常经典，通过不断移位来输出每一个二进制位，需要特别注意该种方法，移位的执行效率是非常之高的
    for(int i=63;i>=0;i--)
    {
        cout<<((input>>i)&1);
    }
}

/*4.
 *convert: 该方法将unsigned long long int类型以64位二进制的形式字符串转化
 *Param: input--需要输出的unsigned long long int类型数字
 *Return:二进制字符串化的输入值input
*/
string SHA512::convert(unsigned long long int input)
{
    //这里使用的算法非常经典，通过不断移位来输出每一个二进制位，需要特别注意该种方法，移位的执行效率是非常之高的
    string res;
    for(int i=63;i>=0;i--)
    {
        res.push_back(((input>>i)&1)+'0');
    }
    return res;
}

/*5.
 *fillString:该方法对原始输入的二进制序列进行填充，填充到长度size符合size%1024==896，然后附加一个128位的填充前长度值序列
 *Param:input--输入二进制序列。返回值:string类型--填充后的二进制序列
*/
string SHA512::fillString(string input)
{
    //1.首先判断是否需要进行填充，需要填充的情况下进行填充
    int osize=input.size();
    if(osize%1024!=896)
    {
        //1.1对于需要填充的情况，第一次填充1，后续每一次填充0，迭代操作直到长度size符合要求为止
        input.push_back('1');
        while(input.size()%1024!=896)
        {
            input.push_back('0');
        }
    }
    //2.在符合条件的序列后添加一个128位二进制序列表示输入二进制序列在填充前的长度值
    string nums(128,'0');
    //2.1首先将原输入字符串长度转化为16进制字符串
    char temp_str[10000];
    sprintf(temp_str,"%x",osize);
    string temp(temp_str);
    temp=hexToBinary(temp_str);
    int m=128-temp.size();
    for(int i=0;i<temp.size();i++)
    {
        nums[m++]=temp[i];
    }
    input+=nums;
    return input;
}

/*6.
 *initDepart: 该方法将N*1024位的二进制字符串拆分为若干1024位的字符串数组
 *Param: input--输入N*1024长度的二进制序列字符串输入，output--N个长度为1024的二进制序列字符串
*/
void SHA512::initDepart(string input,vector<string> &output)
{
    int size=input.size()/1024;
    for(int i=0;i<size;i++)
    {
        string temp;
        for(int k=i*1024;k<(i+1)*1024;k++)
        {
            temp.push_back(input[k]);
        }
        output.push_back(temp);
    }
    return;
}

/*7.
 *cycleRightShift: 实现循环右移
 *Param: a--待移位数，b--移位数
 *Return: 移位结果
*/
unsigned long long int SHA512::cycleRightShift(unsigned long long int a,unsigned long long int b)
{
    unsigned long long int res=a>>b;    //先将a进行右移b位得到结果1
    res|=a<<(64-b);       //再将a进行左移64-b位得到a的后b位，即结果2，最后再将结果1和结果2进行或操作进行合并
    return res;
}

/*8.
 *SHA-512的4个复合操作函数
*/
//复合操作函数Ch
unsigned long long int SHA512::Ch(unsigned long long int e,unsigned long long int f,unsigned long long int g)
{
    return (e&f)^((~e)&g);
}

//复合操作函数Maj
unsigned long long int SHA512::Maj(unsigned long long int a,unsigned long long int b,unsigned long long int c)
{
    return (a&b)^(a&c)^(b&c);
}

//复合操作函数Sigma0
unsigned long long int SHA512::Sigma0(unsigned long long int a)
{
    return cycleRightShift(a,28)^cycleRightShift(a,34)^cycleRightShift(a,39);
}

//复合操作函数Sigma1
unsigned long long int SHA512::Sigma1(unsigned long long int e)
{
    return cycleRightShift(e,14)^cycleRightShift(e,18)^cycleRightShift(e,41);
}

/*9.
 *F: SHA-512的单轮函数F
 *Param: a,b,c,d,e,f,g,h--Hash变量，Wi--64位消息扩展得到的子消息，Ki--轮常量
*/
void SHA512::F(unsigned long long int &a,unsigned long long int &b,unsigned long long int &c,unsigned long long int &d,unsigned long long int &e,unsigned long long int &f,unsigned long long int &g,unsigned long long int &h,unsigned long long int Wi,unsigned long long int Ki)
{
    unsigned long long int T1=h+Ch(e,f,g)+Sigma1(e)+Wi+Ki;
    unsigned long long int T2=Sigma0(a)+Maj(a,b,c);
    h=g;
    g=f;
    f=e;
    e=d+T1;
    d=c;
    c=b;
    b=a;
    a=T1+T2;
    return;
}

/*10.
 *SHA-512的轮常数
*/
const unsigned long long int Ki[80]= {//80个常数
		0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
        0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
        0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
        0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
        0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
        0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
        0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
        0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
        0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
        0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
        0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
        0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
        0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
        0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
        0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
        0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
        0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
        0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
        0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
        0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
        0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

/*11.
 *SHA-512的在消息扩展中所使用的2个复合操作函数
*/
//复合操作函数Theta0
unsigned long long int SHA512::Theta0(unsigned long long int x)
{
    return cycleRightShift(x,1)^cycleRightShift(x,8)^(x>>7);
}

//复合操作函数Theta1
unsigned long long int SHA512::Theta1(unsigned long long int x)
{
    return cycleRightShift(x,19)^cycleRightShift(x,61)^(x>>6);
}

/*12.
 *FExtended: 该方法为轮函数进行消息扩展操作，具体而言，该方法将1024位的二进制序列输入拆分为80个64位二进制的unsigned long long int类型x序列
 *Param: input--1024位输入二进制序列，output--16个64位输出二进制序列(即Wi)
 *Comment: 需要特别注意，在分拆时需要特别注意大端和小端的问题，为了方便，首先对字符串作变换，然后再将字符串转化为unsigned long long int类型
*/
void SHA512::FExtended(string input,unsigned long long int output[80])
{
    //前16个消息扩展结果Wi即为原1024位消息的16个64位分段
    for(int i=0;i<16;i++)
    {
        string temp;
        //首先将字符串作倒装变换
        for(int k=0;k<64;k++)
        {
            temp.push_back(input[i*64+k]);
        }
        //然后将字符串转化为unsigned long long int类型
        output[i]=strtoull(temp.c_str(),0,2);     //string转unsigned long long int常使用内置strtoul来进行快速实现，当然也可以自行实现 
    }
    //后续的消息扩展结果Wi使用固定的公式进行递推扩展
    for(int i=16;i<80;i++)
    {
        output[i]=Theta1(output[i-2])+output[i-7]+Theta0(output[i-15])+output[i-16];
    }
    return;
}

/*13.
 *_SHA512: 该方法对输入的字符串序列进行SHA-512算法，并返回Hash结果
 *Param: input--十六进制输入
 *Return: 十六进制SHA-512 Hash结果输出
*/
string SHA512::_SHA512(string input)
{
    //1.首先将输入消息input进行消息扩展操作
    input=fillString(hexToBinary(input));   //注意首先要将输入的十六进制转化为二进制
    vector<string> lis;
    initDepart(input,lis);
    //2.初始化a,b,c,d,e,f,g,h总共8个轮变量
    unsigned long long int a=0x6a09e667f3bcc908ULL,b=0xbb67ae8584caa73bULL,c=0x3c6ef372fe94f82bULL,d=0xa54ff53a5f1d36f1ULL,e=0x510e527fade682d1ULL,f=0x9b05688c2b3e6c1fULL,g=0x1f83d9abfb41bd6bULL,h=0x5be0cd19137e2179ULL;
    for(int i=0;i<lis.size();i++)
    {
        unsigned long long int A=a,B=b,C=c,D=d,E=e,FF=f,G=g,H=h;

        //3.然后对扩展后的消息进行轮函数消息扩展操作，生成80轮unsigned long long int变量
        unsigned long long int Wi[80];
        FExtended(lis[i],Wi);
        //4.进行80轮轮函数执行和迭代
        for(int k=0;k<80;k++)
        {
            F(a,b,c,d,e,f,g,h,Wi[k],Ki[k]);
        }
        //5.迭代结果加上A,B,C,D,E,F,G,H，得到最终结果
        a+=A; b+=B; c+=C; d+=D; e+=E; f+=FF; g+=G; h+=H;
    }
    //6.将最终的a,b,c,d,e,f,g,h相连即得最终结果
	string res;
	res+=binToHexto(convert(a));
    res+=binToHexto(convert(b));
    res+=binToHexto(convert(c));
    res+=binToHexto(convert(d));
    res+=binToHexto(convert(e));
    res+=binToHexto(convert(f));
    res+=binToHexto(convert(g));
    res+=binToHexto(convert(h));
    return res;
}

