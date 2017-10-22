#include <iostream>
#include <string>

using namespace std;

class MD5 {
public:
	string MD5_encrypt(string &str);

private:
	unsigned int F(unsigned int x, unsigned int y, unsigned int z);
	unsigned int G(unsigned int x, unsigned int y, unsigned int z);
	unsigned int H(unsigned int x, unsigned int y, unsigned int z);
	unsigned int I(unsigned int x, unsigned int y, unsigned int z);

	void MD5_init();
	unsigned int LeftRotate(unsigned int opNumber, unsigned int opBit);

	void FF(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int Mi, unsigned int s, unsigned int Ti);
	void GG(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int Mi, unsigned int s, unsigned int Ti);
	void HH(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int Mi, unsigned int s, unsigned int Ti);
	void II(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int Mi, unsigned int s, unsigned int Ti);

	void UnsignedCharToUnsignedInt(const unsigned char* input, unsigned int* output, size_t length);
	void UnsignedIntToUnsignedChar(const unsigned int* input, unsigned char* output, size_t length);

	string UnsignedCharToHexString(const unsigned char* input);

	void processOfMD5(const unsigned char groups[64]);
	void encryptUnsignedChar(const unsigned char* input, size_t length);
	void final();

	unsigned int state[4];
	unsigned int count[2];
	unsigned char result[16];
	unsigned char buffer[64];

	static const unsigned char padding[64];
};
