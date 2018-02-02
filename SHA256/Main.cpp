#include <iostream>
#include <limits>
#include <stdint.h>
#include <chrono>

#include "SHA256.h"
#include <string>

int main(int argc, char** argv)
{
	//char* input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
	//char* input = "abc";
	

	//std::cout << strlen("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno") << std::endl;
	/*char* input = (char*)malloc(16777216 * 64);
	memset(input, 'a', 1000000);
	input[1000000] = '\0';
	size_t sz = 1000000;*/
	//memset(input, 'a', 16777216 * 64);

	//char* input = new char[496 / 8 + 1];
	//strcpy_s(input, 496 / 8 + 1, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");

	char* input = new char[1073741824 + 1];
	for (int i = 0; i < 16777216; i++)
	{
		memcpy(input + i * 64, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno", 64);
	}
	input[1073741824] = '\0';
	size_t sz = 16777216 * 64;

	//std::string x = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	//for (int i = 0; i < 16777216; i++)
	//{
	//	x.append("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
	//}

	auto before = std::chrono::high_resolution_clock::now();

	unsigned char* sha256 = test::sha256(input, 1073741824);

	auto after = std::chrono::high_resolution_clock::now();

	for (int i = 0; i < 32; i++)
	{
		std::cout << std::hex << (unsigned)sha256[i] << " ";
	}

	std::cout << std::dec << std::endl << std::chrono::duration_cast<std::chrono::milliseconds>(after - before).count() << " ms";

	getchar();
	return 0;
}