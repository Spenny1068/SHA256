#include "sha256.h"
#include <iostream>
#include <string>
using namespace std;


int main(void) {

	string msg = "abc";
	vector<string> hash = sha256(msg);

	cout << "sha256(" << msg << ")=";
	for (unsigned int i = 0; i < hash.size(); i++) {
		cout << hash[i];	
	}
	cout << endl;

	return 0;	
}
