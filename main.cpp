#include "sha256.h"
#include <iostream>

int main(void) {

	std::string msg = "";

	std::cout << "Enter string: ";
	std::cin >> msg;
	std::cout << "sha256(" << msg << "): " << sha256(msg, true) << std::endl;

	return 0;	
}
