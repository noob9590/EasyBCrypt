#pragma once
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <winternl.h>
#include <ntstatus.h>
#include <winerror.h>
#include <stdio.h>
#include <bcrypt.h>
#include <sal.h>
#include <string>
#include <vector>
#include <optional>
#include "base64.h"
#pragma comment( lib, "bcrypt.lib" )

#include <iostream>

namespace EasyBCrypt
{

	using namespace std;

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

	using derived_key = std::vector<BYTE>;

	inline void ReportError(_In_ DWORD dwErrCode)
	{
		wprintf(L"Error: 0x%08x (%d)\n", dwErrCode, dwErrCode);
	}

	optional<vector<BYTE>> Hash(PBYTE bytes, DWORD dwSize);
	optional<vector<BYTE>> Hash(const string& str);

	optional<std::vector<BYTE> >GenerateIV(BCRYPT_ALG_HANDLE hAlg);
	optional<derived_key> KeyFromDerivation(BCRYPT_ALG_HANDLE KdfAlgHandle, const std::vector<BYTE>& key, BCryptBufferDesc kdfParameters, size_t aesRounds = 128);
    optional<std::vector<BYTE>> GenerateKeyBlob(BCRYPT_ALG_HANDLE hAlg, const std::vector<BYTE>& key, const std::wstring& chainingMode);

	optional<std::vector<BYTE>> Encrypt(BCRYPT_ALG_HANDLE hAlg, const std::vector<BYTE>& pbBlob, const std::vector<BYTE>& IV, const std::string& plaintext, bool usePadding = true);
	optional<std::string> Decrypt(BCRYPT_ALG_HANDLE hAlg, const std::vector<BYTE>& pbBlob, const std::vector<BYTE>& IV, const std::vector<BYTE>& ciphertext, bool usePadding = true);

	optional<std::string> Encrypt64(BCRYPT_ALG_HANDLE hAlg, const std::vector<BYTE>& pbBlob, const std::vector<BYTE>& IV, const std::string& plaintext, bool usePadding = true);
	optional<std::string> Decrypt64(BCRYPT_ALG_HANDLE hAlg, const std::vector<BYTE>& pbBlob, const std::vector<BYTE>& IV, const std::string& ciphertext, bool usePadding = true);
}