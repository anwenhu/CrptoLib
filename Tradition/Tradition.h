#include <string>
#include <cmath>

using namespace std;

class Tradition
{
    public:
    Tradition();
    string caesar_encrypt(string plain, int key);
    string caesar_decrypt(string crpt, int key);
    string corr_encrypt(string plain, int a, int b);
    string corr_decrypt(string crpt, int a, int b);
    string vigenere_encrypt(string plain, string key);
    string vigenere_decrypt(string crpt, string key);

    private:
    int __inV(int a, int b, int &x, int &y);
};

/********************* public functions *************************/

/*0.
 *Tradition: 默认构造函数 
 *Param: None 
 *Return: None 
*/
Tradition::Tradition()
{
}

/*1.
 *caesar_encrypt: Caesar加密算法
 *Param: plain--明文；key--密钥
 *Return: 密文
*/
string Tradition::caesar_encrypt(string plain,int key)
{
    string crpt=plain;      //加密后的密文
    string errorcrpt;       //错误密文输出
    if(key<0||key>=26)
    return errorcrpt;
    for(int i=0;i<plain.size();i++)
    {
        if(plain[i]>='a'&&plain[i]<='z')
        {
            crpt[i]='a'+(plain[i]-'a'+key)%26;
        }
        else if(plain[i]>='A'&&plain[i]<='Z')
        {
            crpt[i]='A'+(plain[i]-'A'+key)%26;
        }
        else
        return errorcrpt;
    }
    return crpt;
}

/*2.
 *caesar_decrypt: Caesar解密算法
 *Param: crpt--密文；key--密钥
 *Return: 明文
*/
string Tradition::caesar_decrypt(string crpt,int key)
{
    string plain=crpt;      //加密后的密文
    string errorplain;      //错误明文输出
    if(key<0||key>=26)
    return errorplain;
    for(int i=0;i<crpt.size();i++)
    {
        if(crpt[i]>='a'&&crpt[i]<='z')
        {
            plain[i]='a'+(crpt[i]-'a'-key+26)%26;   //注意crpt[i]-'a'-key的值可能为负数，因此首先需要加上26转化为正数 
        }
        else if(plain[i]>='A'&&plain[i]<='Z')
        {
            plain[i]='A'+(crpt[i]-'A'-key+26)%26;
        }
        else
        return errorplain;
    }
    return plain;
}

/*3. 
 *corr_encrypt: 仿射密码加密
 *Param: plain--明文；a,b--密钥(a,b)，其中加密规则为crpt = (a*plain + b) mod 26
 *Return: 密文
*/
string Tradition::corr_encrypt(string plain,int a,int b)
{
    string crpt=plain;      //加密后的密文
    string errorcrpt;       //错误密文输出
    if(a%2==0||a%13==0)
    return errorcrpt;
    for(int i=0;i<plain.size();i++)
    {
        if(plain[i]>='a'&&plain[i]<='z')
        {
            crpt[i]='a'+((plain[i]-'a')*a+b)%26;
        }
        else if(plain[i]>='A'&&plain[i]<='Z')
        {
            crpt[i]='A'+((plain[i]-'A')*a+b)%26;
        }
        else
        return errorcrpt;
    }
    return crpt;
}

/*4. 
 *corr_decrypt: 仿射密码解密
 *Param: crpt--密文；a,b--密钥(a,b)
 *Return: 明文
*/
string Tradition::corr_decrypt(string crpy,int a,int b)
{
    string plain=crpy;      //解密后的明文
    string errorplain;       //错误明文输出
    if(a%2==0||a%13==0)
    return errorplain;
    int x,y;
    //先求解密钥a相对于26的乘法逆元x
    __inV(a,26,x,y);
    x=(x+26)%26;
    //cout<<"乘法逆元为："<<x<<endl;
    //然后利用该逆元，使用解密方程：plain[i]='a'+(x*((crpy[i]-'a')-b%26+26))%26 进行解密
    for(int i=0;i<crpy.size();i++)
    {
        if(crpy[i]>='a'&&crpy[i]<='z')
        {
            plain[i]='a'+(x*((crpy[i]-'a')-b%26+26))%26;   //详细说明：此处需要特别注意-b%26+26的部分，因为(crpy[i]-'a')的值的范围在0到25之间，而b的值是任意的，b%26便得到了0到25之间范围的数字，这时(crpy[i]-'a')-b%26有可能为负数（最大负值不小于-26），因此需要加上26转化为正数
        }
        else if(crpy[i]>='A'&&crpy[i]<='Z')
        {
            plain[i]='A'+(x*((crpy[i]-'A')-b%26+26))%26;
        }
        else
        return errorplain;
    }
    return plain;
}

/*5.
 *vigenere_encrypt: Vigenere密码加密
 *Param: plain--明文；key--密钥
 *Return: 密文
*/
string Tradition::vigenere_encrypt(string plain,string key)
{
    string crpt=plain;      //加密后的密文
    string errorcrpt;
    for(int i=0;i<plain.size();i++)
    {
        int tempkey=key[i%key.size()]-((key[i%key.size()]>='a'&&key[i%key.size()]<='z')?'a':'A');
        if(plain[i]>='a'&&plain[i]<='z')
        {
            crpt[i]='a'+(plain[i]-'a'+tempkey)%26;
        }
        else if(plain[i]>='A'&&plain[i]<='Z')
        {
            crpt[i]='A'+(plain[i]-'A'+tempkey)%26;
        }
        else
        return errorcrpt;
    }
    return crpt;
}

/*5.
 *vigenere_decrypt: Vigenere密码解密
 *Param: crpt--密文；key--密钥
 *Return: 明文
*/
string Tradition::vigenere_decrypt(string crpt,string key)
{
    string plain=crpt;      //解密后的明文
    string errorplain;      //错误明文输出
    for(int i=0;i<crpt.size();i++)
    {
        int tempkey=key[i%key.size()]-((key[i%key.size()]>='a'&&key[i%key.size()]<='z')?'a':'A');
        if(crpt[i]>='a'&&crpt[i]<='z')
        {
            plain[i]='a'+(crpt[i]-'a'-tempkey+26)%26;   //注意crpt[i]-'a'-key的值可能为负数，因此首先需要加上26转化为正数 
        }
        else if(plain[i]>='A'&&plain[i]<='Z')
        {
            plain[i]='A'+(crpt[i]-'A'-tempkey+26)%26;
        }
        else
        return errorplain;
    }
    return plain;
}

/********************* private functions *************************/

/*1.
 *__inV：扩展欧几里得算法求解乘法逆元
*/
int Tradition::__inV(int a, int b, int &x, int &y)
{
    if (b==0)
    {
        x=1;
        y=0;
        return a;
    }
    int gcd=__inV(b,a%b,x,y);
    int tmp=x;
    x=y;
    y=tmp-(a/b)*y;
    return gcd;
}