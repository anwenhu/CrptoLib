#include "HashCenter.h"

using namespace std;

int main(void)
{
	HashCenter hashcenter("MD5");
	
	string infor="abcdefgh";
	
	string md5_result=hashcenter.gethash(infor,"0x");
	
	hashcenter.reset("SHA512");
	
	string sha512_result=hashcenter.gethash(infor,"0x");
	
	cout<<"MD5 hash结果= "<<md5_result<<endl; 
	cout<<"SHA512 hash结果= "<<sha512_result<<endl; 
}