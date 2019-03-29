#ifndef SHA256_H
#define SHA256_H

#include <string>
#include <vector>

class SHA256
{
private:
	const static unsigned int sha_K[64];	// K constants used in sha-256
	static unsigned int sha_IH[8];			// intermediate hash values used in sha-256
	unsigned int sha_R[8];						// registers array a-h
	unsigned int sha_W[64];						// Expanded message blocks

public:
	//SHA256();		// default constructor
	bool debug;																	// prints intermediate values
	std::vector<std::string> prepare(std::string msg);				// sha256 padding
	void init(int blocks);													// initialize registers 
	std::string loop(std::vector<std::string> V);					// hash computation
	void inter_hash();														// update intermediate hashes
	void update_reg(int i, int j, std::vector<std::string> V);	// update registers a-h
	std::string int_to_string(unsigned int n);						// convert int to string
};

std::string sha256(std::string msg, bool debug_);					// main sha256 function


/* Variable definitions: */
#define SHA256_R(x, n) 			(x >> n)
#define SHA256_S(x, n)			((x >> n) | (x << ((sizeof(x) << 3) - n)))

/* Logical function macros */
#define SHA256_ch(x, y, z)		((x & y) ^ (~x & z))	
#define SHA256_maj(x, y, z)	((x & y) ^ (x & z) ^ (y & z))
#define SHA256_e0(x)				(SHA256_S(x, 2) ^ SHA256_S(x, 13) ^ SHA256_S(x, 22))
#define SHA256_e1(x)				(SHA256_S(x, 6) ^ SHA256_S(x, 11) ^ SHA256_S(x, 25))
#define SHA256_sig0(x)			(SHA256_S(x, 7) ^ SHA256_S(x, 18) ^ SHA256_R(x, 3))
#define SHA256_sig1(x)			(SHA256_S(x, 17) ^ SHA256_S(x, 19) ^ SHA256_R(x, 10))

#endif
