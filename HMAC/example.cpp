#include "HMAC.h"
#include <iostream>
#include <string>

using namespace std;

int main(void)
{
	string plain="616263";
	string key="616263";
	string result;
	
	HMAC hmac=HMAC();
	
	result=hmac.getMac(plain,key,"sha512","0x","0x");
	cout<<"sha512 mac result: "<<result<<endl;
	
	result=hmac.getMac(plain,key,"md5","0x","0x");
	cout<<"md5 mac result: "<<result<<endl;
}