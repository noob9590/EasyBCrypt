#pragma once
#include <windows.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <optional>
#include <memory>
#include "base64.h"
#pragma comment( lib, "bcrypt.lib" )

#include <iostream>

namespace EasyBCrypt
{

	using namespace std;

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

	inline void ReportError(_In_ DWORD dwErrCode)
	{
		wprintf(L"Error: 0x%08x (%d)\n", dwErrCode, dwErrCode);
	}

	optional<vector<BYTE>> Hash(PBYTE bytes, DWORD dwSize);
	optional<vector<BYTE>> Hash(string& str);

	optional<std::vector<BYTE> >GenerateIV(BCRYPT_ALG_HANDLE hAlg);
    optional<std::vector<BYTE>> GenerateSymmetricKeyHandle(BCRYPT_ALG_HANDLE hAlg, std::vector<BYTE> key, const std::wstring& chainingMode);

	optional<std::vector<BYTE>> Encrypt(BCRYPT_ALG_HANDLE hAlg, std::vector<BYTE> pbBlob, std::vector<BYTE> IV, std::string plaintext);
	optional<std::string> Decrypt(BCRYPT_ALG_HANDLE hAlg, std::vector<BYTE> pbBlob, std::vector<BYTE> IV, std::vector<BYTE> ciphertext);

	optional<std::string> Encrypt64(BCRYPT_ALG_HANDLE hAlg, std::vector<BYTE> pbBlob, std::vector<BYTE> IV, std::string plaintext);
	optional<std::string> Decrypt64(BCRYPT_ALG_HANDLE hAlg, std::vector<BYTE> pbBlob, std::vector<BYTE> IV, std::string ciphertext);
}