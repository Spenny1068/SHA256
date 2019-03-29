#include "sha256.h"
#include <iostream>
using namespace std;

int main(void) {

	string msg = "";

	cout << "Enter string: ";
	cin >> msg;
	cout << "sha256(" << msg << "): " << sha256(msg, false) << endl;

	return 0;	
}
