#include <iostream>
#include "EBcrypt.h"
#include <fstream>
#include <sstream>



// functions for debugging
void PrintBytes(
	IN BYTE* pbPrintData,
	IN DWORD    cbDataLen)
{
	DWORD dwCount = 0;

	for (dwCount = 0; dwCount < cbDataLen; dwCount++)
	{
		printf("0x%02x, ", pbPrintData[dwCount]);

		if (dwCount + 1 % 32 == 0)
			std::cout << std::endl;
	}
	std::cout << std::endl;

}

void Print(IN char* pbPrintData,
	IN DWORD    cbDataLen)
{
	for (size_t i = 0; i < cbDataLen; i++)
	{
		if (i % cbDataLen > 25 and pbPrintData[i % cbDataLen] == ' ')
			std::cout << std::endl;
		std::cout << pbPrintData[i];
	}
	std::cout << std::endl;
}


// Cipher class
class AESCipher
{
public:
	AESCipher(std::vector<BYTE> key);
	~AESCipher();
	std::vector<BYTE> Encrypt(std::vector<BYTE> IV, std::string plaintText);
	std::string Encrypt64(std::vector<BYTE> IV, std::string plaintText);
	std::string Decrypt(std::vector<BYTE> IV, std::vector<BYTE> cipherText);
	std::string Decrypt64(std::vector<BYTE> IV, std::string cipherText);
	

private:
	BCRYPT_ALG_HANDLE hAlg;
	std::vector<BYTE> pbBlob;
};

AESCipher::AESCipher(std::vector<BYTE> key)
{
	// Initialize the provider
	if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(
		&hAlg,
		BCRYPT_AES_ALGORITHM,
		NULL,
		0)))
	{
		std::wcout << L"**** Error returned by BCryptOpenAlgorithmProvider\n";
		ExitProcess(1); // need to raise an exception here...
	}

	// generate key blob for import/export the key
	auto optPbPlob = EasyBCrypt::GenerateSymmetricKeyHandle(hAlg, key, BCRYPT_CHAIN_MODE_CBC);
	if (not optPbPlob)
	{
		std::wcout << "Error returned by GenerateSymmetricKeyHandle\n";
		ExitProcess(1); // need to raise an exception here...
	}

	pbBlob = optPbPlob.value();
}

AESCipher::~AESCipher()
{
	BCryptCloseAlgorithmProvider(hAlg, 0);
}

std::vector<BYTE> AESCipher::Encrypt(std::vector<BYTE> IV, std::string plaintText)
{
	auto optEncryption = EasyBCrypt::Encrypt(hAlg, pbBlob, IV, plaintText);
	if (not optEncryption)
		return std::vector<BYTE>();
	return optEncryption.value();
}


std::string AESCipher::Encrypt64(std::vector<BYTE> IV, std::string plaintText)
{
	auto optEncryption64 = EasyBCrypt::Encrypt64(hAlg, pbBlob, IV, plaintText);
	if (not optEncryption64)
		return "";
	return optEncryption64.value();
}

std::string AESCipher::Decrypt(std::vector<BYTE> IV, std::vector<BYTE> cipherText)
{
	auto optDecryption = EasyBCrypt::Decrypt(hAlg, pbBlob, IV, cipherText);
	if (not optDecryption)
		return "";
	return optDecryption.value();
}

std::string AESCipher::Decrypt64(std::vector<BYTE> IV, std::string cipherText)
{
	auto optDecryption64 = EasyBCrypt::Decrypt64(hAlg, pbBlob, IV, cipherText);
	if (not optDecryption64)
		return "";
	return optDecryption64.value();
}

int main()
{
	// part of an encrypted shellcode
	std::string encryptedShellcode = "swOMfhzDLZBhVQO1u+wXjsJ8IR0IcIKIAA+RrXtLasmrhylhyQC7NyfYnXXHOFspaz0IHk6efpcqgm8QISgmJ7fiTnrzZCVS8aEvwEbQQA1QVL4JEoJtWdB+YJOIdx61VOTc3HMY3VJ4dXEv3yMKX57bj19t0RKsRaqNCYAOszw8w29b0aQ9LR47AMiquR+RIzGCIvI5ADHfSGMQJA3o9/q7kYdNSK4+JSs9T123GknAM091/WF4vT4EI6s8qpV7eTqeLjt92qw5D+CW7xq7yye61G+ECjWz+83HkwMUOQEpU13GMIbWve44AlwOf2coEvF+NlLFrMis2p8oVAKEIvcr0F8zNK3D/iVI2UlaxtLxu2rwxKhFmm993tFJ7KhuRKy3R4cBFTxen+iulltzlq35x2F2DeMgsI/5b6HZ04glycdVCziTIZGDsDOq2q8GdCoTUyWJ4MiFot521yq7OXKzFiuoR4l4ww7Ky4B/fk2ZHA2YN92cptRzaRB/wOkXBAfZqzATMEwDQbBmkRocBPio8L/hTe9lP3H40/PiGgo=";

	std::vector<BYTE> key =
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	};

	std::vector<BYTE> IV =
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	};

	auto optHashedKey = EasyBCrypt::Hash(key.data(), sizeof(key));
	if (not optHashedKey)
	{
		std::wcout << "[-] Failed to hash the key." << std::endl;
		ExitProcess(1);
	}

	std::vector<BYTE> hashedKey = optHashedKey.value();

	AESCipher cipher(key);
	std::string shellcode = cipher.Decrypt64(IV, encryptedShellcode);

	PrintBytes((BYTE*)shellcode.data(), shellcode.size());


}