#include "Tradition.h"
#include <iostream>
#include <string>

using namespace std;

int main(void)
{
	Tradition trad;
	
	//Caesar
	string plain="abcdefghijklmnopqrstuvwxyz";
	string crpt;
	int key=3;
	
	crpt=trad.caesar_encrypt(plain,key);
	cout<<"Caesar encrypt = "<<crpt<<endl;
	plain=trad.caesar_decrypt(crpt,key);
	cout<<"Caesar decrypt = "<<plain<<endl;
	
	//Corr
	string plain1="abcdefghijklmnopqrstuvwxyz";
	string crpt1;
	int a=3, b=3;
	
	crpt1=trad.corr_encrypt(plain1,a,b);
	cout<<"Corr encrypt = "<<crpt1<<endl;
	plain1=trad.corr_decrypt(crpt1,a,b);
	cout<<"Corr decrypt = "<<plain1<<endl;
	
	//Vigenere
	string plain2="abcdefghijklmnopqrstuvwxyz";
	string crpt2;
	string key2="abcdefghijklmnopqrstuvwxyz";
	
	crpt2=trad.vigenere_encrypt(plain2,key2);
	cout<<"Vigenere encrypt = "<<crpt2<<endl;
	plain2=trad.vigenere_decrypt(crpt2,key2);
	cout<<"CVigenere decrypt = "<<plain2<<endl;
	
}
