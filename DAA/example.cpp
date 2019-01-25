#include "DAA.h" 

using namespace std;

int main(void)
{
	string plain="616263";
	string key="6162636465666768";
	string enpt;
	
	DAA daa=DAA();
	enpt=daa.getDac(plain,key,"0x","0x");
	
	cout<<"DAA result: "<<enpt<<endl;
}