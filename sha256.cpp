#include "sha256.h"
//#include <cstring>	// memset
#include <iostream>
#include <bitset>
//#include <string>
//#include <vector>

// The first 32-bits of the fractional parts of the cube roots of the first 64 primes
const unsigned int SHA256::sha_K[64] = 
		{0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
       0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
       0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
       0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
       0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
       0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
       0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
       0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
       0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
       0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
       0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
       0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
       0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
       0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
       0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
       0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
	



// initialize registers a, b, c, d, e, f, g, h with the initial hash value 
// The initial hash value is 32-bit words obtained by taking the fractional parts of the 
// square roots of the first eight primes
void SHA256::init() {
	sha_H[0] = 0x6a09e667;	// register a
	sha_H[1] = 0xbb67ae85;	// register b
	sha_H[2] = 0x3c6ef372;	// register c
	sha_H[3] = 0xa54ff53a;	// register d
	sha_H[4] = 0x510e527f;	// register e
	sha_H[5] = 0x9b05688c;	// register f
	sha_H[6] = 0x1f83d9ab;	// register g
	sha_H[7] = 0x5be0cd19;	// register h
	
	std::cout << "init: " << std::hex << sha_H[0] << " "
						       << std::hex << sha_H[1] << " "
 						       << std::hex << sha_H[2] << " "
 						       << std::hex << sha_H[3] << " "
 						       << std::hex << sha_H[4] << " "
 						       << std::hex << sha_H[5] << " "
 						       << std::hex << sha_H[6] << " "
						       << std::hex << sha_H[7] << " ";
	std::cout << "\n";
}


// Preprocessing: Prepare the message by padding the message
std::vector<std::string> SHA256::prepare(std::string msg) {

	std::string paddedStr = "";
	std::vector<std::string> vec;
	const int BLOCK_SIZE = 512;

	// convert string to binary string
	for (std::size_t i = 0; i < msg.size(); i++) {
		std::string temp = (std::bitset<8>(msg[i])).to_string();
		paddedStr += temp;
	}

	// define l to be the length of msg in bits
	int l = paddedStr.length();	

	// append the bit "1" to the end of the message
	paddedStr += "1";

	// append k zero bits, where k is the smallest non-neg solution to l + 1 + k = 448 mod 512
	int k = (448 % 512) - (l + 1);
	std::string zeros(k, '0');
	//char zeros[k];
	//memset(zeros, '0', k);
	paddedStr += zeros;

	// append the 64-bit block which is equal to the number l written in binary 
	std::string num = std::bitset<64>(l).to_string();
	paddedStr += num;

	// parse the message into N 512-bit blocks M^(1), M^(2), ... M^(N).
	// The first 32 bits of the message block i are denoted M0^(i), the next 32 bits are
	// M1^(i) and so on up to M15^(i).  We use big-endian convention
	for (unsigned int i = 0; i < paddedStr.length() / BLOCK_SIZE; i++) {
		vec.push_back(paddedStr.substr(i * BLOCK_SIZE, BLOCK_SIZE));
	}

	return vec;
}



// Hash computation
void SHA256::loop(std::vector<std::string> V, bool itm, bool debug) {

	int N = V.size();
	unsigned int temp, T1, T2 = 0;
	const int WORD = 32;
	

	// for i = 1 to N (N = number of blocks in the padded message)
	for (int i = 1; i <= N; i++) {

		// set iteration 0 hash values
		init();

		// apply SHA-256 compression function to update intermediate values
		for(int j = 0; j < 64; j++) {

			// calculate expanded message blocks W0, W1, ... W63
			if (j < 16) {

				// convert 32-bit word from padded message to integer
				std::string W = V[0].substr(j * WORD, WORD);
				temp = stoi(W, nullptr, 2);
			}

			// pre calculations
			unsigned int chEFG = SHA256_ch(sha_H[4], sha_H[5], sha_H[6]);	
			int majABC = SHA256_maj(sha_H[0], sha_H[1], sha_H[2]);
			int e0A = SHA256_e0(sha_H[0]);
			int e1E = SHA256_e1(sha_H[4]);

			/* T1 = h + e1(e) + ch(e, f, g) + Kj + Wj */
			T1 = sha_H[7] + e1E + chEFG + sha_K[j] + temp;

			/* T2 = e0(a) + maj(a, b, c) */
			T2 = e0A + majABC;

			/* h = g */
			sha_H[7] = sha_H[6];

			/* g = f */
			sha_H[6] = sha_H[5];

			/* f = e */
			sha_H[5] = sha_H[4];

			/* e = d + T1 */
			sha_H[4] = sha_H[3] + T1;

			/* d = c */
			sha_H[3] = sha_H[2];

			/* c = b */
			sha_H[2] = sha_H[1];

			/* b = a */
			sha_H[1] = sha_H[0];	

			/* a = T1 + T2 */
			sha_H[0] = T1 + T2;


			// print out debug values for each iteration
			if (debug) {
				std::cout << "W[" << std::dec << j << "]: " << std::hex << temp << ", ";
				std::cout << "K[" << std::dec << j << "]: " << std::hex << sha_K[j] << ", ";
				std::cout << "chEFG: " << std::hex << chEFG << ", ";
				std::cout << "e1E: " << std::hex << e1E << ", ";
				std::cout << "T1: " << std::hex << T1 << ", ";
				//std::cout << "T2" << std::hex << T2 << ", ";
				std::cout << "\n";
			}

			// print out intermediate values for each iteration
			if (itm) {
				std::cout << "t = " << std::dec << j << ": " 
					      			  << std::hex << sha_H[0] << " "
										  << std::hex << sha_H[1] << " "
										  << std::hex << sha_H[2] << " "
										  << std::hex << sha_H[3] << " "
										  << std::hex << sha_H[4] << " "
										  << std::hex << sha_H[5] << " "
										  << std::hex << sha_H[6] << " "
										  << std::hex << sha_H[7] << " ";
				std::cout << "\n";
			}
		}
	}
	
}

// Main function that returns sha256 hash
std::vector<std::string> sha256(std::string msg) {

	SHA256 ob;

	// prepare message with sha256 padding
	std::vector<std::string> preparedMsg = ob.prepare(msg);

	// compute hash(intermediate, debug)
	ob.loop(preparedMsg, true, false); 
	// return sha256(msg)
	return preparedMsg;
}
