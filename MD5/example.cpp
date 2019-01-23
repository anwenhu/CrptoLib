#include "MD5.h"
#include <iostream>
#include <string>

using namespace std;

int main(void)
{
	string plain="6a6b6c6d6e";
	string enpt;
	
    MD5 md5=MD5();
	
	enpt=md5.hash(plain,"0x","0x");
	cout<<"hash result: "<<enpt<<endl;
}