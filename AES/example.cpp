#include "AES.h"
#include <iostream>
#include <string>

using namespace std;

int main(void)
{
	string plain="0123456789abcdeffedcba9876543210";
	string key="0f1571c947d9e8590cb7add6af7f6798";
	string enpt;
	
	AES aes=AES();
	aes.key(key,"0x");
	
	enpt=aes.encrypt(plain,"0x","0x");
	cout<<"encrypt result: "<<enpt<<endl;
	
	plain=aes.decrypt(enpt,"0x","0x");
	cout<<"decrypt result: "<<plain<<endl;
}
