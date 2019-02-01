#include "Pattern - DEV.h"

using namespace std;

int main(void)
{
	string plain="abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghab";
	string key="abcdefghabcdefgh";   //aes使用32位十六进制密钥，每个字母对应两位二进制 
	string vec="abcdefghabcdefgh";
	string crpt; 
	cout<<"明文="<<plain<<endl;
	
	Pattern pat=Pattern("AES","CFB");
	crpt=pat.encrypt(plain, key, vec, "0x");
	cout<<"加密得到的密文="<<crpt<<endl;
	
	//plain=pat.decrypt(crpt, key, "0x");
	//cout<<"重新解密得到的明文="<<plain<<endl;
}