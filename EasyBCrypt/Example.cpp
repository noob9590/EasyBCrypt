#include <iostream>
#include "EBcrypt.h"
#include <fstream>
#include <sstream>


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

void epilouge(BCRYPT_ALG_HANDLE hAlg, BCRYPT_ALG_HANDLE hKdf)
{
	BCryptCloseAlgorithmProvider(hAlg, 0);
	BCryptCloseAlgorithmProvider(hKdf, 0);
}

int main()
{
	//plaintext
	std::string plaintext = "CanYouReadIt???CanYouReadIt???CanYouReadIt???";

	//handles
	BCRYPT_ALG_HANDLE hAlg;
	BCRYPT_ALG_HANDLE hKdf;

	//key
	std::vector<BYTE> key = 
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F 
	};

	//salt
	BYTE Salt[] =
	{
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	};

	//number of iteration for the kdf algorithm
	ULONGLONG IterationCount = 1024;

	// PBKDF2 parameters
	BCryptBuffer PBKDF2ParameterBuffers[] = {
									{
										sizeof(BCRYPT_SHA256_ALGORITHM),
										KDF_HASH_ALGORITHM,
										(PVOID)BCRYPT_SHA256_ALGORITHM,
									},
									{
										sizeof(Salt),
										KDF_SALT,
										(PBYTE)Salt,
									},
									{
										sizeof(IterationCount),
										KDF_ITERATION_COUNT,
										(PBYTE)&IterationCount,
									}
	};

	BCryptBufferDesc PBKDF2Parameters = {
										BCRYPTBUFFER_VERSION,
										3,
										PBKDF2ParameterBuffers
	};

	// vector to store the initialization vector
	std::vector<BYTE> IV;
	// vector to store the ciphertext
	std::vector<BYTE> ciphertext;
	// string to store the decrypted result
	std::string decipherText;


	// Open an algorithm handle.
	if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(
		&hAlg,
		BCRYPT_AES_ALGORITHM,
		NULL,
		0)))
	{
		std::cout << "Error returned by BCryptOpenAlgorithmProvider" << std::endl;
		ExitProcess(1);
	}

	// open kdf provider
	if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(
		&hKdf,
		BCRYPT_PBKDF2_ALGORITHM,
		NULL,
		0
	)))
	{
		std::cout << "Error returned by BCryptOpenAlgorithmProvider" << std::endl;
		BCryptCloseAlgorithmProvider(hAlg, 0);
		ExitProcess(1);
	}

	// here we used aes128 which is the default algorithm
	EasyBCrypt::derived_key dKey;
	auto optDerivedKey = EasyBCrypt::KeyFromDerivation(hKdf, key, PBKDF2Parameters); 
	if (not optDerivedKey)
	{
		std::cout << "Failed to key from PBKDF2. Exiting..." << std::endl;
		epilouge(hAlg, hKdf);
		ExitProcess(1);
	}
	
	dKey = std::move(*optDerivedKey);


	std::vector<BYTE> pbBlob;
	auto optPbBlob = EasyBCrypt::GenerateKeyBlob(hAlg, dKey, BCRYPT_CHAIN_MODE_CBC);
	if (not optPbBlob)
	{
		std::cout << "[-] Failed to generate symmetric key. Exiting..." << std::endl;
		epilouge(hAlg, hKdf);
		ExitProcess(1);
	}

	pbBlob = std::move(*optPbBlob);


	auto optIV = EasyBCrypt::GenerateIV(hAlg);
	if (not optIV)
	{
		std::cout << "[-] Failed to generate IV. Exiting..." << std::endl;
		epilouge(hAlg, hKdf);
		ExitProcess(1);
	}

	IV = std::move(*optIV);

	auto optCiphertext = EasyBCrypt::Encrypt(hAlg, pbBlob, IV, plaintext);
	if (not optCiphertext)
	{
		std::cout << "[-] Failed to generate ciphertext. Exiting..." << std::endl;
		epilouge(hAlg, hKdf);
		ExitProcess(1);
	}

	ciphertext = std::move(*optCiphertext);

	std::cout << "\n[+] Ciphertext: " << std::endl;

	PrintBytes(ciphertext.data(), ciphertext.size());



	// decrypt data
	auto optDeciphertext = EasyBCrypt::Decrypt(hAlg, pbBlob, IV, ciphertext);
	if (not optDeciphertext)
	{
		std::cout << "[-] Failed to decrypt the cipher. Exiting..." << std::endl;
		epilouge(hAlg, hKdf);
		ExitProcess(1);
	}

	decipherText = std::move(*optDeciphertext);

	std::cout << "\n[+] Plaintext: " << std::endl;

	Print(decipherText.data(), decipherText.size());

	if (decipherText == plaintext)
		std::cout << "\nSuccess : Plaintext has been encrypted, ciphertext has been decrypted with AES-128 bit key" << std::endl;
	else
		std::cout << "\nFailed : Plaintext has been encrypted, ciphertext could not have been decrypted." << std::endl;

}