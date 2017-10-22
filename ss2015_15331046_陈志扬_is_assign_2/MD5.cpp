#include "MD5.h"

const unsigned char MD5::padding[64] = { 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
												0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
												0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
												0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

/**
 * Args：str表示待加密文本
 * Func：MD5算法主函数
 * Return：MD5加密后的值
 */
string MD5::MD5_encrypt(string &str) {
	MD5_init();
	encryptUnsignedChar((const unsigned char*)(str.c_str()), str.length());
	final();
	string MD5_value = UnsignedCharToHexString(result);
	return MD5_value;
}

/**
 * Args：空
 * Func：初始化链接变量
 * Return：空
 */
void MD5::MD5_init() {
	count[0] = 0;
	count[1] = 0;

	state[0] = 0x67452301;
	state[1] = 0xefcdab89;
	state[2] = 0x98badcfe;
	state[3] = 0x10325476;
}

/**
 * @Initialization the md5 object, processing another message block,
 * and updating the context.
 *
 * @param {input} the input message.
 *
 * @param {length} the number btye of message.
 *
 */
void MD5::encryptUnsignedChar(const unsigned char* input, size_t length) {
	unsigned int index, partLen;
	size_t i;

	/* Compute number of bytes mod 64 */
	index = static_cast<unsigned int>((count[0] >> 3) & 0x3f);
	/* update number of bits */
	if ((count[0] += (static_cast<unsigned int>(length) << 3)) 
		< (static_cast<unsigned int>(length) << 3)) {
		count[1]++;
	}
	count[1] +=  (static_cast<unsigned int>(length) >> 29);

	partLen = 64 - index;

	/* transform as many times as possible. */
	if (length >= partLen) {
		memcpy(&buffer[index], input, partLen);
		processOfMD5(buffer);
		for (i = partLen; i + 63 < length; i += 64) {
			processOfMD5(&input[i]);
		}
		index = 0;
	}
	else {
		i = 0;
	}
	/* Buffer remaining input */
	memcpy(&buffer[index], &input[i], length - i);
}

/**
 * Args：groups[]表示一个512位（64字节）分组
 * Func：四轮主要操作
 * Return：空
 */
void MD5::processOfMD5(const unsigned char groups[64]) {
	unsigned int a = state[0], b = state[1], c = state[2], d = state[3];
	unsigned int M[16];

	UnsignedCharToUnsignedInt(groups, M, 64);
	// 第一轮循环
	FF(a, b, c, d, M[0], 7, 0xd76aa478);
	FF(d, a, b, c, M[1], 12, 0xe8c7b756);
	FF(c, d, a, b, M[2], 17, 0x242070db);
	FF(b, c, d, a, M[3], 22, 0xc1bdceee);
	FF(a, b, c, d, M[4], 7, 0xf57c0faf);
	FF(d, a, b, c, M[5], 12, 0x4787c62a);
	FF(c, d, a, b, M[6], 17, 0xa8304613);
	FF(b, c, d, a, M[7], 22, 0xfd469501);
	FF(a, b, c, d, M[8], 7, 0x698098d8);
	FF(d, a, b, c, M[9], 12, 0x8b44f7af);
	FF(c, d, a, b, M[10], 17, 0xffff5bb1);
	FF(b, c, d, a, M[11], 22, 0x895cd7be);
	FF(a, b, c, d, M[12], 7, 0x6b901122);
	FF(d, a, b, c, M[13], 12, 0xfd987193);
	FF(c, d, a, b, M[14], 17, 0xa679438e);
	FF(b, c, d, a, M[15], 22, 0x49b40821);
	// 第二轮循环
	GG(a, b, c, d, M[ 1], 5, 0xf61e2562);
	GG(d, a, b, c, M[ 6], 9, 0xc040b340);
	GG(c, d, a, b, M[11], 14, 0x265e5a51);
	GG(b, c, d, a, M[ 0], 20, 0xe9b6c7aa);
	GG(a, b, c, d, M[ 5], 5, 0xd62f105d);
	GG(d, a, b, c, M[10], 9,  0x2441453);
	GG(c, d, a, b, M[15], 14, 0xd8a1e681);
	GG(b, c, d, a, M[ 4], 20, 0xe7d3fbc8);
	GG(a, b, c, d, M[ 9], 5, 0x21e1cde6);
	GG(d, a, b, c, M[14], 9, 0xc33707d6);
	GG(c, d, a, b, M[ 3], 14, 0xf4d50d87);
	GG(b, c, d, a, M[ 8], 20, 0x455a14ed);
	GG(a, b, c, d, M[13], 5, 0xa9e3e905);
	GG(d, a, b, c, M[ 2], 9, 0xfcefa3f8);
	GG(c, d, a, b, M[ 7], 14, 0x676f02d9);
	GG(b, c, d, a, M[12], 20, 0x8d2a4c8a);
	// 第三轮循环
	HH(a, b, c, d, M[ 5], 4, 0xfffa3942);
	HH(d, a, b, c, M[ 8], 11, 0x8771f681);
	HH(c, d, a, b, M[11], 16, 0x6d9d6122);
	HH(b, c, d, a, M[14], 23, 0xfde5380c);
	HH(a, b, c, d, M[ 1], 4, 0xa4beea44);
	HH(d, a, b, c, M[ 4], 11, 0x4bdecfa9);
	HH(c, d, a, b, M[ 7], 16, 0xf6bb4b60);
	HH(b, c, d, a, M[10], 23, 0xbebfbc70);
	HH(a, b, c, d, M[13], 4, 0x289b7ec6);
	HH(d, a, b, c, M[ 0], 11, 0xeaa127fa);
	HH(c, d, a, b, M[ 3], 16, 0xd4ef3085);
	HH(b, c, d, a, M[ 6], 23,  0x4881d05);
	HH(a, b, c, d, M[ 9], 4, 0xd9d4d039);
	HH(d, a, b, c, M[12], 11, 0xe6db99e5);
	HH(c, d, a, b, M[15], 16, 0x1fa27cf8);
	HH(b, c, d, a, M[ 2], 23, 0xc4ac5665);
	// 第四轮循环
	II(a, b, c, d, M[ 0], 6, 0xf4292244);
	II(d, a, b, c, M[ 7], 10, 0x432aff97);
	II(c, d, a, b, M[14], 15, 0xab9423a7);
	II(b, c, d, a, M[ 5], 21, 0xfc93a039);
	II(a, b, c, d, M[12], 6, 0x655b59c3);
	II(d, a, b, c, M[ 3], 10, 0x8f0ccc92);
	II(c, d, a, b, M[10], 15, 0xffeff47d);
	II(b, c, d, a, M[ 1], 21, 0x85845dd1);
	II(a, b, c, d, M[ 8], 6, 0x6fa87e4f);
	II(d, a, b, c, M[15], 10, 0xfe2ce6e0);
	II(c, d, a, b, M[ 6], 15, 0xa3014314);
	II(b, c, d, a, M[13], 21, 0x4e0811a1);
	II(a, b, c, d, M[ 4], 6, 0xf7537e82);
	II(d, a, b, c, M[11], 10, 0xbd3af235);
	II(c, d, a, b, M[ 2], 15, 0x2ad7d2bb);
	II(b, c, d, a, M[ 9], 21, 0xeb86d391);

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}

/**
 * Args：input表示输入字节char数组，output表示输出unsigned int数组，length表示字节长度
 * Func：unsigned char转成unsigned int（左低右高）
 * Return：空
 */
void MD5::UnsignedCharToUnsignedInt(const unsigned char* input, unsigned int* output, size_t length) {
	for (size_t i = 0, j = 0; j < length; i++, j += 4) {
		output[i] = ((static_cast<unsigned int>(input[j]))
					 | ((static_cast<unsigned int>(input[j + 1])) << 8)
					 | ((static_cast<unsigned int>(input[j + 2])) << 16)
					 | ((static_cast<unsigned int>(input[j + 3])) << 24));
	}
}

/**
 * Args：opNumber表示待左移的数，opBit表示左移的位数
 * Func：完成循环左移操作
 * Return：循环左移后的结果
 */
unsigned int MD5::LeftRotate(unsigned int opNumber, unsigned int opBit) {
	unsigned int left = opNumber;
	unsigned int right = opNumber;
	return (left << opBit) | (right >> (32 - opBit));
}

void MD5::FF(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int Mi, unsigned int s, unsigned int Ti) {
	unsigned int temp = a + F(b, c, d) + Mi + Ti;
	a = b + LeftRotate(temp, s);
}

void MD5::GG(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int Mi, unsigned int s, unsigned int Ti) {
	unsigned int temp = a + G(b, c, d) + Mi + Ti;
	a = b + LeftRotate(temp, s);
}

void MD5::HH(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int Mi, unsigned int s, unsigned int Ti) {
	unsigned int temp = a + H(b, c, d) + Mi + Ti;
	a = b + LeftRotate(temp, s);
}

void MD5::II(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int Mi, unsigned int s, unsigned int Ti) {
	unsigned int temp = a + I(b, c, d) + Mi + Ti;
	a = b + LeftRotate(temp, s);
}

unsigned int MD5::F(unsigned int x, unsigned int y, unsigned int z) {
	return (x & y) | ((~x) & z);
}

unsigned int MD5::G(unsigned int x, unsigned int y, unsigned int z) {
	return (x & z) | (y & (~z));
}

unsigned int MD5::H(unsigned int x, unsigned int y, unsigned int z) {
	return x ^ y ^ z;
}

unsigned int MD5::I(unsigned int x, unsigned int y, unsigned int z) {
	return y ^ (x | (~z));
}

/**
 * @Generate md5 digest.
 *
 */
void MD5::final() {
	unsigned char bits[8];
	unsigned int oldState[4], oldCount[2];
	unsigned int index, padLen;

	/* Save current state and count. */
	memcpy(oldState, state, 16);
	memcpy(oldCount, count, 8);

	/* Save number of bits */
	UnsignedIntToUnsignedChar(count, bits, 8);

	/* Pad out to 56 mod 64. */
	index = static_cast<unsigned int>((count[0] >> 3) & 0x3f);
	padLen = (index < 56) ? (56 - index) : (120 - index);
	encryptUnsignedChar(padding, padLen);

	/* Append length (before padding) */
	encryptUnsignedChar(bits, 8);

	/* Store state in digest */
	UnsignedIntToUnsignedChar(state, result, 16);

	/* Restore current state and count. */
	memcpy(state, oldState, 16);
	memcpy(count, oldCount, 8);
}

/**
 * Args：input表示unsigned int数组，output表示输出字节char数组，length表示输入字节长度
 * Func：unsigned int转成unsigned char
 * Return：空
 */
void MD5::UnsignedIntToUnsignedChar(const unsigned int* input, unsigned char* output, size_t length) {
	for (size_t i = 0, j = 0; j < length; i++, j += 4) {
		output[j] = static_cast<unsigned char>(input[i] & 0xff);
		output[j + 1] = static_cast<unsigned char>((input[i] >> 8) & 0xff);
		output[j + 2] = static_cast<unsigned char>((input[i] >> 16) & 0xff);
		output[j + 3] = static_cast<unsigned char>((input[i] >> 24) & 0xff);
	}
}

/**
 * Args：input表示生成的信息摘要digest
 * Func：unsigned char转成16进制输出
 * Return：16进制字符串以输出
 */
string MD5::UnsignedCharToHexString(const unsigned char* input) {
	const char charToHex[16] = {'0', '1', '2', '3', '4', '5', '6', '7', 
								'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	string str;
	for (size_t i = 0; i < 16; i++) {
		unsigned int temp = static_cast<unsigned int>(input[i]);
		unsigned int a = temp / 16;
		unsigned int b = temp % 16;
		str.append(1, charToHex[a]);
		str.append(1, charToHex[b]);
	}
	return str;
}
