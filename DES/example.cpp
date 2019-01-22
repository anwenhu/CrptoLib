#include "DES.h"
#include <iostream>
#include <string>

using namespace std;

int main(void)
{
	string plain="02468aceeca86420";
	string key="0f1571c947d9e859";
	string enpt;
	
	DES des=DES();
	des.key(key,"0x");
	
	enpt=des.encrypt(plain,"0x","0x");
	cout<<"encrypt result: "<<enpt<<endl;
	
	plain=des.decrypt(enpt,"0x","0x");
	cout<<"ecrypt result: "<<plain<<endl;
}