#include "SHA256.h"
#include <memory>
#include <stdint.h>
#include <iostream>

namespace test
{

	template <typename T>
	constexpr T rotr(T x, int n) {
		return ((x >> n) | (x << (sizeof(T) * CHAR_BIT - n)));
	}

	template <typename T>
	constexpr T rotl(T x, int n) {
		return ((x << n) | (x >> (sizeof(T) * CHAR_BIT - n)));
	}

	template <typename T>
	constexpr T SHR(T x, int n)
	{
		return (x >> n);
	}

	template <typename T>
	constexpr T CH(T x, T y, T z)
	{
		return ((x)& (y)) ^ ((~(x)) & (z));
	}

	template <typename T>
	constexpr T MAJ(T x, T y, T z)
	{
		return ((x)& (y)) ^ ((x)& (z)) ^ ((y)& (z));
	}

	template <typename T>
	constexpr T BSIG0(T x)
	{
		return (rotr((x), 2) ^ rotr((x), 13) ^ rotr((x), 22));
	}

	template <typename T>
	constexpr T BSIG1(T x)
	{
		return (rotr((x), 6) ^ rotr((x), 11) ^ rotr((x), 25));
	}

	template <typename T>
	constexpr T SSIG0(T x)
	{
		return (rotr((x), 7) ^ rotr((x), 18) ^ SHR((x), 3));
	}

	template <typename T>
	constexpr T SSIG1(T x)
	{
		return (rotr((x), 17) ^ rotr((x), 19) ^ SHR((x), 10));
	}

	const unsigned int K[] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
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
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};



	inline unsigned long long swapLong(unsigned long long x)
	{
		x = (x & 0x00000000FFFFFFFF) << 32 | (x & 0xFFFFFFFF00000000) >> 32;
		x = (x & 0x0000FFFF0000FFFF) << 16 | (x & 0xFFFF0000FFFF0000) >> 16;
		x = (x & 0x00FF00FF00FF00FF) << 8 | (x & 0xFF00FF00FF00FF00) >> 8;
		return x;
	}

	inline unsigned int swapInt(unsigned int x)
	{
		x = (x & 0x0000FFFF) << 16 | (x & 0xFFFF0000) >> 16;
		x = (x & 0x00FF00FF) << 8 | (x & 0xFF00FF00) >> 8;
		return x;
	}

	struct MESSAGE
	{
		uint32_t words[16];
	};

	struct WORKING
	{
		uint32_t words[64];
	};

	struct SHA256Context
	{
		SHA256Context(const unsigned char* input, long long length) :
			stream_(input)
		{
			blocksCount_ = length / 64;
			long long lengthBit = length * 8;

			if (lengthBit % 512 < 448)
			{
				lastBlock_ = new unsigned char[64];
				memset(lastBlock_, 0x0, 64);
				memcpy(lastBlock_, input + blocksCount_ * 64, length % 64);
				memset(lastBlock_ + length % 64, 0x80, 1);

				unsigned long long szReversed = swapLong(length * 8);
				memcpy(lastBlock_ + 56, reinterpret_cast<unsigned char*>(&szReversed), sizeof(szReversed));
			}
			else
			{
				secondToLastBlock_ = new unsigned char[64];
				memset(secondToLastBlock_, 0x0, 64);
				memcpy(secondToLastBlock_, input + blocksCount_ * 64, length % 64);
				memset(secondToLastBlock_ + length % 64, 0x80, 1);

				lastBlock_ = new unsigned char[64];
				memset(lastBlock_, 0x0, 64);
				unsigned long long szReversed = swapLong(length * 8);
				memcpy(lastBlock_ + 56, reinterpret_cast<unsigned char*>(&szReversed), sizeof(szReversed));

				blocksCount_ += 1;
			}

			blocksCount_ += 1;
		}

		void showBlocks()
		{
			const unsigned char* block = nullptr;
			while ((block = nextBlock()) != nullptr)
			{
				showBlock(block);
			}
		}

		const unsigned char* nextBlock()
		{
			const unsigned char* retValue = nullptr;
			if (blocksCount_ - currentBlock_ == 2 && secondToLastBlock_ != nullptr)
			{
				retValue = secondToLastBlock_;
			}
			else if (blocksCount_ - currentBlock_ == 1)
			{
				retValue = lastBlock_;
			}
			else if(currentBlock_ < blocksCount_)
			{
				retValue = (stream_ + (currentBlock_) * 64);
			}
	
			currentBlock_++;
			return retValue;
		}

		void showHex()
		{
			if (secondToLastBlock_ != nullptr)
				showBlock(secondToLastBlock_);
			showBlock(lastBlock_);
		}

		void showBlock(const unsigned char* block)
		{
			for (int i = 0; i < 64; i += 4)
			{
				std::cout << "0x";
				for (int j = 0; j < 4; j++)
				{
					if (block[i + j] == 0)
					{
						std::cout << "00";
					}
					else
					{
						std::cout << std::hex << (unsigned) block[i + j];
					}
				}
				std::cout << " ";
			}
			std::cout << std::endl;
		}

		const unsigned char* stream_;
		long long blocksCount_ = 0;
		long long currentBlock_ = 0;
		unsigned char* lastBlock_ = nullptr;
		unsigned char* secondToLastBlock_ = nullptr;
	};

	unsigned char* sha256(const char* input, long long length)
	{
		static unsigned int H[] = {
			0x6a09e667,
			0xbb67ae85,
			0x3c6ef372,
			0xa54ff53a,
			0x510e527f,
			0x9b05688c,
			0x1f83d9ab,
			0x5be0cd19
		};

		SHA256Context context(reinterpret_cast<const unsigned char*>(input), length);

		WORKING W;
		uint32_t a, b, c, d, e, f, g, h;
		const unsigned char* current = nullptr;
		while((current = context.nextBlock()) != nullptr)
		{
			const MESSAGE* M = (reinterpret_cast<const MESSAGE*>(current));
			for (int t = 0; t < 16; t++)
			{
				W.words[t] = swapInt(M->words[t]);
				//W.words[t] = *(reinterpret_cast<const uint32_t*>(current + t * 4));
			}
			for (int t = 16; t < 64; t++)
			{
				W.words[t] = SSIG1(W.words[t - 2]) + W.words[t - 7] + SSIG0(W.words[t - 15]) + W.words[t - 16];
			}

			a = H[0];
			b = H[1];
			c = H[2];
			d = H[3];
			e = H[4];
			f = H[5];
			g = H[6];
			h = H[7];

			for (int t = 0; t < 64; t++)
			{
				const uint32_t sige = BSIG1(e);
				const uint32_t cgefg = CH(e, f, g);
				const uint32_t bsig0a = BSIG0(a);
				const uint32_t majabc = MAJ(a, b, c);
				const uint32_t T1 = h + sige + cgefg + K[t] + W.words[t];
				const uint32_t T2 = bsig0a + majabc;
				h = g;
				g = f;
				f = e;
				e = d + T1;
				d = c;
				c = b;
				b = a;
				a = T1 + T2;
			}
			H[0] = a + H[0];
			H[1] = b + H[1];
			H[2] = c + H[2];
			H[3] = d + H[3];
			H[4] = e + H[4];
			H[5] = f + H[5];
			H[6] = g + H[6];
			H[7] = h + H[7];
		}

		unsigned char* retVal = new unsigned char[32];
		for (int i = 0; i < 8; i++)
		{
			uint32_t temp = swapInt(H[i]);
			memcpy(retVal + (i * sizeof(H[i])), &temp, sizeof(temp));
		}

		return retVal;
	}

}
