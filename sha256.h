#ifndef SHA256_H
#define SHA256_H

#include <string>
#include <vector>

class SHA256
{
private:
	unsigned int sha_H[8];		// initial hash values
	const static unsigned int sha_K[64];		// K constants used in sha-256

public:
	//SHA256();	// default constructor
	void init();	// initialize with H^(0) hash values 
	std::vector<std::string> prepare(std::string msg);		// prepare the message with sha256 padding
	void loop(std::vector<std::string> V, bool debug) ;	// main loop for hash computation
};

std::vector<std::string> sha256(std::string msg);	// main sha256 function

// Variable definitons:
// R^(n) = right shift by n bits
// S^(n) = right rotation by n bits
// + = mod 2^32 addition

// Logical function definitions
// Ch(x,y,z) = (x AND y) XOR (complement(x) AND Z)
// Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
// E0(x) = S^2(x) XOR S^13(x) XOR S^22(x)
// E1(x) = S^6(x) XOR S^11(x) XOR S^25(x)
// sig0(x) = S^7(x) XOR S^18(x) XOR R^3(x)
// sig1(x) = S^17(x) XOR S^19(x) XOR R^10(x)


// Logical function macros
#define SHA256_R(x, n) 			(x >> n)
#define SHA256_S(x, n)			((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define SHA256_ch(x, y, z)		((x & y) ^ (~x & z))	
#define SHA256_maj(x, y, z)	((x & y) ^ (x & z) ^ (y & z))
#define SHA256_e0(x)				(SHA256_S(x, 2) ^ SHA256_S(x, 13) ^ SHA256_S(x, 22))
#define SHA256_e1(x)				(SHA256_S(x, 6) ^ SHA256_S(x, 11) ^ SHA256_S(x, 25))
#define SHA256_sig0(x)			(SHA256_S(x, 7) ^ SHA256_S(x, 18) ^ SHA256_R(x, 3))
#define SHA256_sig1(x)			(SHA256_S(x, 17) ^ SHA256_S(x, 19) ^ SHA256_R(x, 10))
#define SHA256_W

#endif
