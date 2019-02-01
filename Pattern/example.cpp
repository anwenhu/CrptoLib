#include "Pattern.h"

using namespace std;

int main(void)
{
	string plain="abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghab";
	string key="abcdefghabcdefgh";   //aes使用32位十六进制密钥，每个字母对应两位二进制 
	string vec="abcdefghabcdefgh";
	string crpt0, crpt1, crpt2, crpt3, crpt4; 
	cout<<"明文="<<plain<<endl;
	
	Pattern pat0=Pattern("AES","ECB");
	Pattern pat1=Pattern("AES","CBC");
	Pattern pat2=Pattern("AES","CFB");
	Pattern pat3=Pattern("AES","OFB");
	Pattern pat4=Pattern("AES","CTR");
	
	crpt0=pat0.encrypt(plain, key, vec, "0x");
	cout<<"ECB加密得到的密文="<<crpt0<<endl<<endl;
	
	crpt1=pat1.encrypt(plain, key, vec, "0x");
	cout<<"CBC加密得到的密文="<<crpt1<<endl<<endl;
	
	crpt2=pat2.encrypt(plain, key, vec, "0x");
	cout<<"CFB加密得到的密文="<<crpt2<<endl<<endl;
	
	crpt3=pat3.encrypt(plain, key, vec, "0x");
	cout<<"OFB加密得到的密文="<<crpt3<<endl<<endl;
	
	crpt4=pat4.encrypt(plain, key, vec, "0x");
	cout<<"CTR加密得到的密文="<<crpt4<<endl<<endl;
	
	//plain=pat.decrypt(crpt, key, "0x");
	//cout<<"重新解密得到的明文="<<plain<<endl;
}