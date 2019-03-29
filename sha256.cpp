#include "sha256.h"
#include <iostream>
#include <bitset>
#include <sstream>

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

// The initial hash value is 32-bit words obtained by taking the fractional parts of the 
// square roots of the first eight primes
unsigned int SHA256::sha_IH[8] = 
		{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};


// initialize registers a, b, c, d, e, f, g, h with the (i-1) intermediate hash value
inline void SHA256::init(int blocks) {
	sha_R[0] = sha_IH[0];		// register a
	sha_R[1] = sha_IH[1];		// register b
	sha_R[2] = sha_IH[2];		// register c
	sha_R[3] = sha_IH[3];		// register d
	sha_R[4] = sha_IH[4];		// register e
	sha_R[5] = sha_IH[5];		// register f
	sha_R[6] = sha_IH[6];		// register g
	sha_R[7] = sha_IH[7];		// register h
	
	// print out initial register values
	if (debug) {
		std::cout << "\n				BLOCK " << blocks << std::endl;
		std::cout << "init: " << std::hex << sha_R[0] << " "
									 << std::hex << sha_R[1] << " "
									 << std::hex << sha_R[2] << " "
									 << std::hex << sha_R[3] << " "
									 << std::hex << sha_R[4] << " "
									 << std::hex << sha_R[5] << " "
									 << std::hex << sha_R[6] << " "
									 << std::hex << sha_R[7] << " ";
		std::cout << "\n";
	}
}


// Preprocessing: Prepare the message by padding the message
inline std::vector<std::string> SHA256::prepare(std::string msg) {

	std::string paddedStr = "";
	std::vector<std::string> vec;
	const int BLOCK_SIZE = 512;

	// convert string to binary string
	for (unsigned int i = 0; i < msg.size(); i++) {
		std::string temp = (std::bitset<8>(msg[i])).to_string();
		paddedStr += temp;
	}

	// define l to be the length of msg in bits
	int l = paddedStr.length();	

	// append the bit "1" to the end of the message
	paddedStr += "1";

	// append k zero bits, where k is the smallest non-neg solution to l + 1 + k = 448 mod 512
	int k = (448 % 512) - (l + 1);

	//FIXME -> only works for 6 blocks or less
	if (k <= 0) { k = 512 * (paddedStr.length() / 448) - paddedStr.length() + 448; }
	std::string zeros(k, '0');
	paddedStr += zeros;

	// append the 64-bit block which is equal to the number l written in binary 
	std::string num = std::bitset<64>(l).to_string();
	paddedStr += num;

	// parse the message into N 512-bit blocks
	for (unsigned int i = 0; i < paddedStr.length() / BLOCK_SIZE; i++) { 
		vec.push_back(paddedStr.substr(i * BLOCK_SIZE, BLOCK_SIZE));
	}

	return vec;
}



// Hash computation
std::string SHA256::loop(std::vector<std::string> V) {

	std::string sha256_hash = "";

	// for i = 1 to (number of blocks in the padded message)
	for (unsigned int i = 1; i <= V.size(); i++) 
	{
		init(i);		// initialize registers a-h with (i-1)th intermediate hash value
		for(int j = 0; j < 64; j++) 
		{
			update_reg(i, j, V);		// update registers h
		}

	std::cout << "\n";
	inter_hash();	// compute the ith intermediate hash value

	}

	// construct the full hash of the message
	for (int i = 0; i < 8; i++) {
		sha256_hash += int_to_string(sha_IH[i]);
		sha256_hash += " ";
	}

	return sha256_hash;
}

// apply SHA-256 compression function to update registers a-h
inline void SHA256::update_reg(int i, int j, std::vector<std::string> vec) {

	int W, T1, T2 = 0;
	const int WORD = 32;

	// calculate intermediate values chEFG, majABC, e0A, e1E
	int chEFG = SHA256_ch(sha_R[4], sha_R[5], sha_R[6]);	
	int majABC = SHA256_maj(sha_R[0], sha_R[1], sha_R[2]);
	int e0A = SHA256_e0(sha_R[0]);
	int e1E = SHA256_e1(sha_R[4]);

	// calculate expanded message blocks W0, W1, ... W63
	if (j < 16) {

		// convert 32-bit word from padded message to integer
		std::string temp = vec[i - 1].substr(j * WORD, WORD);
		W = stol(temp, nullptr, 2);
		sha_W[j] = W;
	}

	else {
		W = SHA256_sig1(sha_W[j-2]) + sha_W[j-7] + SHA256_sig0(sha_W[j-15]) + sha_W[j-16];
		sha_W[j] = W;
	}

	/* T1 = h + e1(e) + ch(e, f, g) + Kj + Wj */
	T1 = sha_R[7] + e1E + chEFG + sha_K[j] + W;

	/* T2 = e0(a) + maj(a, b, c) */
	T2 = e0A + majABC;

	/* h = g */
	sha_R[7] = sha_R[6];

	/* g = f */
	sha_R[6] = sha_R[5];

	/* f = e */
	sha_R[5] = sha_R[4];

	/* e = d + T1 */
	sha_R[4] = sha_R[3] + T1;

	/* d = c */
	sha_R[3] = sha_R[2];

	/* c = b */
	sha_R[2] = sha_R[1];

	/* b = a */
	sha_R[1] = sha_R[0];	

	/* a = T1 + T2 */
	sha_R[0] = T1 + T2;


	// print out intermediate register values for each iteration
	if (debug) {
		std::cout << "t = " << std::dec << j << ": " 
								  << std::hex << sha_R[0] << " "
								  << std::hex << sha_R[1] << " "
								  << std::hex << sha_R[2] << " "
								  << std::hex << sha_R[3] << " "
								  << std::hex << sha_R[4] << " "
								  << std::hex << sha_R[5] << " "
								  << std::hex << sha_R[6] << " "
								  << std::hex << sha_R[7] << " ";
		std::cout << "\n";
	}
}

// calculate intermediate hashes
inline void SHA256::inter_hash() {

	// compute the ith intermediate hash values
	
	/* H1^(i) = a + H1^(i-1) */
	sha_IH[0] = sha_R[0] + sha_IH[0];
	
	/* H2^(i) = b + H2^(i-1) */
	sha_IH[1] = sha_R[1] + sha_IH[1];

	/* H3^(i) = c + H3^(i-1) */
	sha_IH[2] = sha_R[2] + sha_IH[2];

	/* H4^(i) = d + H4^(i-1) */
	sha_IH[3] = sha_R[3] + sha_IH[3];

	/* H5^(i) = e + H5^(i-1) */
	sha_IH[4] = sha_R[4] + sha_IH[4];

	/* H6^(i) = f + H6^(i-1) */
	sha_IH[5] = sha_R[5] + sha_IH[5];

	/* H7^(i) = g + H7^(i-1) */
	sha_IH[6] = sha_R[6] + sha_IH[6];

	/* H8^(i) = h + H8^(i-1) */
	sha_IH[7] = sha_R[7] + sha_IH[7];
}

// Main function that returns sha256 hash
std::string sha256(std::string msg, bool debug_) {

	SHA256 ob;
	ob.debug = debug_;

	// prepare message with sha256 padding
	std::vector<std::string> preparedMsg = ob.prepare(msg);

	// compute hash(intermediate)
	std::string hash = ob.loop(preparedMsg); 
	return hash;
}

// converts a hex integer to hex string
inline std::string SHA256::int_to_string(unsigned int n) {
	std::stringstream ss;
	ss << std::hex << n;
	std::string hex_str(ss.str());
	return hex_str;
}

