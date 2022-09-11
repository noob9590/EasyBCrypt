//#include <iostream>
//#include "EBcrypt.h"
//#include <fstream>
//#include <sstream>
//
//
//void PrintBytes(
//	IN BYTE* pbPrintData,
//	IN DWORD    cbDataLen)
//{
//	DWORD dwCount = 0;
//
//	for (dwCount = 0; dwCount < cbDataLen; dwCount++)
//	{
//		printf("0x%02x, ", pbPrintData[dwCount]);
//
//		if (dwCount + 1 % 32 == 0)
//			std::cout << std::endl;
//	}
//	std::cout << std::endl;
//
//}
//
//void Print(IN char* pbPrintData,
//	IN DWORD    cbDataLen)
//{
//	for (size_t i = 0; i < cbDataLen; i++)
//	{
//		if (i % cbDataLen > 25 and pbPrintData[i % cbDataLen] == ' ')
//			std::cout << std::endl;
//		std::cout << pbPrintData[i];
//	}
//	std::cout << std::endl;
//}
//
//int main()
//{
//	BCRYPT_ALG_HANDLE hAlg;
//	std::string plaintext = "CanYouReadIt?";
//	std::vector<BYTE> key = 
//	{
//		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F 
//	};
//	std::vector<BYTE> IV;
//	std::vector<BYTE> ciphertext;
//	std::string decipherText;
//
//	std::cout << "[+] Creating AES Provider." << std::endl;
//	// Open an algorithm handle.
//	if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(
//		&hAlg,
//		BCRYPT_AES_ALGORITHM,
//		NULL,
//		0)))
//	{
//		wprintf(L"**** Error returned by BCryptOpenAlgorithmProvider\n");
//		ExitProcess(1);
//	}
//
//	std::cout << "[+] Generate Symmetric Key." << std::endl;
//
//	std::vector<BYTE> pbBlob;
//	auto optPbBlob = EasyBCrypt::GenerateSymmetricKeyHandle(hAlg, key, BCRYPT_CHAIN_MODE_CBC);
//
//	if (not optPbBlob)
//	{
//		std::cout << "[-] Failed to generate symmetric key. Exiting..." << std::endl;
//		ExitProcess(1);
//	}
//
//	pbBlob = optPbBlob.value();
//
//	std::cout << "[+] Generate IV." << std::endl;
//
//	auto optIV = EasyBCrypt::GenerateIV(hAlg);
//	if (not optIV)
//	{
//		std::cout << "[-] Failed to generate IV. Exiting..." << std::endl;
//		ExitProcess(1);
//	}
//
//	IV = optIV.value();
//
//	std::cout << "[+] Generate ciphertext." << std::endl;
//
//	auto optCiphertext = EasyBCrypt::Encrypt(hAlg, pbBlob, IV, plaintext);
//	if (not optCiphertext)
//	{
//		std::cout << "[-] Failed to generate ciphertext. Exiting..." << std::endl;
//		ExitProcess(1);
//	}
//
//	ciphertext = optCiphertext.value();
//
//	std::cout << "\n[+] Cipher: " << std::endl;
//
//	PrintBytes(ciphertext.data(), ciphertext.size());
//
//
//	auto optDeciphertext = EasyBCrypt::Decrypt(hAlg, pbBlob, IV, ciphertext);
//	if (not optDeciphertext)
//	{
//		std::cout << "[-] Failed to decrypt the cipher. Exiting..." << std::endl;
//		ExitProcess(1);
//	}
//
//	decipherText = optDeciphertext.value();
//
//	std::cout << "\n[+] Decipher: " << std::endl;
//
//	Print(decipherText.data(), decipherText.size());
//}