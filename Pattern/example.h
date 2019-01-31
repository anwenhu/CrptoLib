#include "Pattern - DEV.h"

using namespace std;

int main(void)
{
	string plain="abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghab";
	string key="abcdefghabcdefghabcdefghabcdefgh";
	string vec="abcdefghabcdefghabcdefghabcdefgh";
	string crpt; 
	cout<<"明文="<<plain<<endl;
	
	Pattern pat=Pattern("AES","CBC");
	crpt=pat.encrypt(plain, key, vec, "0x");
	cout<<"加密得到的密文="<<crpt<<endl;
	
	//plain=pat.decrypt(crpt, key, "0x");
	//cout<<"重新解密得到的明文="<<plain<<endl;
}