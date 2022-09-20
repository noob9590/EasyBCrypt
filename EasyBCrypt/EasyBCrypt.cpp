#include "EasyBCrypt.h"

std::optional<std::vector<BYTE>> EasyBCrypt::Hash(PBYTE bytes, DWORD dwSize)
{
;
	BCRYPT_ALG_HANDLE		hAlgHash;
	BCRYPT_HASH_HANDLE      hHash = NULL;
	NTSTATUS                status = STATUS_UNSUCCESSFUL;
	DWORD                   cbData = 0,
							cbHash = 0,
							cbHashObject = 0;
	unique_ptr<BYTE[]>      pbHashObject = NULL;
	std::vector<BYTE>		pbHashOut;

	// Open an algorithm handle.
	if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(
		&hAlgHash,
		BCRYPT_SHA256_ALGORITHM,
		NULL,
		0)))
	{
		wprintf(L"**** Error returned by BCryptOpenAlgorithmProvider\n");
		ExitProcess(1);
	}

	//calculate the size of the buffer to hold the hash object
	if (!NT_SUCCESS(status = BCryptGetProperty(
		hAlgHash,
		BCRYPT_OBJECT_LENGTH,
		reinterpret_cast<PBYTE>( & cbHashObject),
		sizeof(DWORD),
		&cbData,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
		goto Cleanup;
	}

	//allocate the hash object on the heap
	pbHashObject = make_unique<BYTE[]>(cbHashObject);

	//calculate the length of the hash
	if (!NT_SUCCESS(status = BCryptGetProperty(
		hAlgHash,
		BCRYPT_HASH_LENGTH,
		reinterpret_cast<PBYTE>( & cbHash),
		sizeof(DWORD),
		&cbData,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
		goto Cleanup;
	}

	//create a hash
	if (!NT_SUCCESS(status = BCryptCreateHash(
		hAlgHash,
		&hHash,
		pbHashObject.get(),
		cbHashObject,
		NULL,
		0,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptCreateHash\n", status);
		goto Cleanup;
	}


	//hash some data
	if (!NT_SUCCESS(status = BCryptHashData(
		hHash,
		reinterpret_cast<PBYTE>(bytes),
		dwSize,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptHashData\n", status);
		goto Cleanup;
	}

	// resize the vector to the hash size
	pbHashOut.resize(cbHash);

	//close the hash
	if (!NT_SUCCESS(status = BCryptFinishHash(
		hHash,
		pbHashOut.data(),
		cbHash,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptFinishHash\n", status);
		goto Cleanup;
	}



Cleanup:

	if (hAlgHash)
	{
		BCryptCloseAlgorithmProvider(hAlgHash, 0);
	}

	if (hHash)
	{
		BCryptDestroyHash(hHash);
	}

	if (not NT_SUCCESS(status)) return std::nullopt;

	return pbHashOut;
		
}

std::optional<std::vector<BYTE>> EasyBCrypt::Hash(const string& str)
{
	auto optHash = Hash(reinterpret_cast<PBYTE>(const_cast<char*>(str.data())), static_cast<DWORD>(str.size()));
	if (not optHash) return nullopt;

	return optHash.value();
}

std::optional<std::vector<BYTE> > EasyBCrypt::GenerateIV(BCRYPT_ALG_HANDLE hAlg, DWORD IVSize /* = -1 */)
{
	NTSTATUS status;
	DWORD IVSize;
	DWORD res;
	std::vector<BYTE> IV;
	std::wstring mode(32, 0);

	status = BCryptGetProperty(
		hAlg,
		BCRYPT_CHAINING_MODE,
		reinterpret_cast<PBYTE>(mode.data()),
		(mode.size() + 1) * sizeof(wchar_t),
		&res,
		0);

	if (not NT_SUCCESS(status))
	{
		ReportError(status);
		return nullopt;
	}

	if (IVSize == -1)
		if (wcscmp(mode.c_str(), BCRYPT_CHAIN_MODE_CBC) == 0 or \
			wcscmp(mode.c_str(), BCRYPT_CHAIN_MODE_CFB) == 0)
		{
			IVSize = 16;
		}
		else if (wcscmp(mode.c_str(), BCRYPT_CHAIN_MODE_GCM) == 0 or \
			wcscmp(mode.c_str(), BCRYPT_CHAIN_MODE_CCM) == 0)
		{
			IVSize = 12;
		}
		else
		{
			IVSize = 0;
		}

	IV.resize(IVSize);

	status = BCryptGenRandom(
		NULL,										// Alg Handle pointer; If NULL, the default provider is chosen
		reinterpret_cast<PBYTE>(IV.data()),         // Address of the buffer that receives the random number(s)
		IVSize,								// Size of the buffer in bytes
		BCRYPT_USE_SYSTEM_PREFERRED_RNG);			// Flags 

	if (not NT_SUCCESS(status))
	{
		ReportError(status);
		return nullopt;
	}
		

	return IV;
}

std::optional<std::vector<BYTE>> EasyBCrypt::GenerateKeyBlob(BCRYPT_ALG_HANDLE hAlg, const std::vector<BYTE>& key, const std::wstring& chainingMode)
{
	NTSTATUS status;
	BCRYPT_KEY_HANDLE hKey;
	std::vector<BYTE> pbBlob;
	DWORD cbBlob;
	DWORD chainingModeLength = (chainingMode.size() + 1) * sizeof(wchar_t);

	status = BCryptGenerateSymmetricKey(
		hAlg,																// Algorithm provider handle
		&hKey,																// A pointer to key handle
		NULL,																// A pointer to the buffer that recieves the key object;NULL implies memory is allocated and freed by the function
		0,																	// Size of the buffer in bytes
		reinterpret_cast<BYTE*>(const_cast<unsigned char*>(key.data())),    // A pointer to a buffer that contains the key material
		static_cast<ULONG>(key.size()),										// Size of the buffer in bytes
		0);																	// Flags

	if (not NT_SUCCESS(status))
	{
		ReportError(status);
		return std::nullopt;
	}
		

	status = BCryptSetProperty(
		hKey,																// Handle to a CNG object          
		BCRYPT_CHAINING_MODE,												// Property name(null terminated unicode string)
		reinterpret_cast<PBYTE>(const_cast<wchar_t*>(chainingMode.data())), // Address of the buffer that contains the new property value 
		chainingModeLength,													// Size of the buffer in bytes
		0);																	// Flags

	if (not NT_SUCCESS(status))
	{
		ReportError(status);
		BCryptDestroyKey(hKey);
		return std::nullopt;
	}
		

	// Save another copy of the key for later.
	status = BCryptExportKey(
		hKey,
		NULL,
		BCRYPT_OPAQUE_KEY_BLOB,
		NULL,
		0,
		&cbBlob,
		0);

	if (not NT_SUCCESS(status))
	{
		ReportError(status);
		BCryptDestroyKey(hKey);
		return std::nullopt;
	}
		

	pbBlob.resize(cbBlob);

	status = BCryptExportKey(
		hKey,
		NULL,
		BCRYPT_OPAQUE_KEY_BLOB,
		pbBlob.data(),
		cbBlob,
		&cbBlob,
		0);

	if (not NT_SUCCESS(status))
	{
		ReportError(status);
		BCryptDestroyKey(hKey);
		return std::nullopt;
	}
		

	status = BCryptDestroyKey(hKey);
		
	if (not NT_SUCCESS(status))
	{
		ReportError(status);
		return std::nullopt;
	}
		
	return pbBlob;
}


std::optional<std::vector<BYTE>> EasyBCrypt::Encrypt(BCRYPT_ALG_HANDLE hAlg, const std::vector<BYTE>& pbBlob, const std::vector<BYTE>& IV, const std::string& plaintext, bool usePadding)
{
	NTSTATUS status;
	BCRYPT_KEY_HANDLE hKey;
	std::vector<BYTE> enc;
	std::unique_ptr<BYTE[]> tmpIV = make_unique<BYTE[]>(IV.size());
	PBYTE PTRtmpIV = tmpIV.get();
	ULONG CipherTextLength;
	ULONG res;

	status = BCryptImportKey(
		hAlg,
		NULL,
		BCRYPT_OPAQUE_KEY_BLOB,
		&hKey,
		NULL,
		0,
		reinterpret_cast<PBYTE>(const_cast<unsigned char*>(pbBlob.data())),
		static_cast<ULONG>(pbBlob.size()),
		0);
																

	if (not NT_SUCCESS(status))
	{
		ReportError(status);
		return std::nullopt;
	}
		

	memcpy(PTRtmpIV, IV.data(), IV.size());

	if (not NT_SUCCESS(status))
	{
		ReportError(status);
		BCryptDestroyKey(hKey);
		return std::nullopt;
	}

	status = BCryptEncrypt(
		hKey,															// Handle to a key which is used to encrypt 
		reinterpret_cast<BYTE*>(const_cast<char*>(plaintext.data())),   // Address of the buffer that contains the plaintext
		static_cast<ULONG>(plaintext.size()),							// Size of the buffer in bytes
		NULL,															// A pointer to padding info, used with asymmetric and authenticated encryption; else set to NULL
		PTRtmpIV,														// Address of the buffer that contains the IV. 
		static_cast<ULONG>(IV.size()),									// Size of the IV buffer in bytes
		NULL,															// Address of the buffer the receives the ciphertext
		0,																// Size of the buffer in bytes
		&CipherTextLength,												// Variable that receives number of bytes copied to ciphertext buffer 
		usePadding ? BCRYPT_BLOCK_PADDING : 0);											// Flags; Block padding allows to pad data to the next block size

	if (not NT_SUCCESS(status))
	{
		ReportError(status);
		BCryptDestroyKey(hKey);
		return nullopt;
	}
		

	enc.resize(CipherTextLength);

	status = BCryptEncrypt(
		hKey,															// Handle to a key which is used to encrypt 
		reinterpret_cast<BYTE*>(const_cast<char*>(plaintext.data())),   // Address of the buffer that contains the plaintext
		static_cast<ULONG>(plaintext.size()),							// Size of the buffer in bytes
		NULL,															// A pointer to padding info, used with asymmetric and authenticated encryption; else set to NULL
		PTRtmpIV,														// Address of the buffer that contains the IV. 
		static_cast<ULONG>(IV.size()),									// Size of the IV buffer in bytes
		reinterpret_cast<PBYTE>(enc.data()),							// Address of the buffer the receives the ciphertext
		CipherTextLength,												// Size of the buffer in bytes
		&res,															// Variable that receives number of bytes copied to ciphertext buffer 
		usePadding ? BCRYPT_BLOCK_PADDING : 0);											// Flags; Block padding allows to pad data to the next block size

	if (not NT_SUCCESS(status))
	{
		ReportError(status);
		BCryptDestroyKey(hKey);
		return nullopt;
	}
		
	status = BCryptDestroyKey(hKey);

	if (not NT_SUCCESS(status))
	{
		ReportError(status);
		return nullopt;
	}

	return enc;
}

std::optional<std::string> EasyBCrypt::Decrypt(BCRYPT_ALG_HANDLE hAlg, const std::vector<BYTE>& pbBlob, const std::vector<BYTE>& IV, const std::vector<BYTE>& ciphertext, bool usePadding)
{
	NTSTATUS status;
	std::string dec;
	BCRYPT_KEY_HANDLE hKey;
	std::unique_ptr<BYTE[]> tmpIV = make_unique<BYTE[]>(IV.size());
	PBYTE PTRtmpIV = tmpIV.get();
	ULONG plaintextLength;
	ULONG res;

	status = BCryptImportKey(
		hAlg,
		NULL,
		BCRYPT_OPAQUE_KEY_BLOB,
		&hKey,
		NULL,
		0,
		reinterpret_cast<BYTE*>(const_cast<unsigned char*>(pbBlob.data())),
		(ULONG)pbBlob.size(),
		0);


	if (not NT_SUCCESS(status))
	{
		ReportError(status);
		return std::nullopt;
	}
	

	memcpy(PTRtmpIV, IV.data(), IV.size());

	status = BCryptDecrypt(
		hKey,																	// Handle to a key which is used to encrypt 
		reinterpret_cast<BYTE*>(const_cast<unsigned char*>(ciphertext.data())),	// Address of the buffer that contains the ciphertext
		static_cast<ULONG>(ciphertext.size()),									// Size of the buffer in bytes
		NULL,																	// A pointer to padding info, used with asymmetric and authenticated encryption; else set to NULL
		PTRtmpIV,																// Address of the buffer that contains the IV. 
		static_cast<ULONG>(IV.size()),											// Size of the IV buffer in bytes
		NULL,																	// Address of the buffer the recieves the plaintext
		0,																		// Size of the buffer in bytes
		&plaintextLength,														// Variable that recieves number of bytes copied to plaintext buffer 
		usePadding ? BCRYPT_BLOCK_PADDING : 0);

	if (not NT_SUCCESS(status))
	{
		ReportError(status);
		BCryptDestroyKey(hKey);
		return nullopt;
	}
		
	dec.resize(plaintextLength);

	status = BCryptDecrypt(
		hKey,																	// Handle to a key which is used to encrypt 
		reinterpret_cast<BYTE*>(const_cast<unsigned char*>(ciphertext.data())), // Address of the buffer that contains the ciphertext
		static_cast<ULONG>(ciphertext.size()),									// Size of the buffer in bytes
		NULL,																	// A pointer to padding info, used with asymmetric and authenticated encryption; else set to NULL
		PTRtmpIV,																// Address of the buffer that contains the IV. 
		static_cast<ULONG>(IV.size()),											// Size of the IV buffer in bytes
		reinterpret_cast<PBYTE>(dec.data()),									// Address of the buffer the recieves the plaintext
		plaintextLength,														// Size of the buffer in bytes
		&res,																	// Variable that recieves number of bytes copied to plaintext buffer 
		usePadding ? BCRYPT_BLOCK_PADDING : 0);

	if (not NT_SUCCESS(status))
	{
		if (status == 0xC000003E)
			std::cout << "[!] An error occurred in reading or writing data. Probably due to an incorrect IV or key was supplied." << std::endl;

		else
		{
			ReportError(status);
			BCryptDestroyKey(hKey);
			return nullopt;
		}
	}

	status = BCryptDestroyKey(hKey);

	if (not NT_SUCCESS(status))
	{
		ReportError(status);
		return std::nullopt;
	}

	dec.resize(res);
	dec.shrink_to_fit();

	return dec;
}

std::optional<std::string> EasyBCrypt::Encrypt64(BCRYPT_ALG_HANDLE hAlg, const std::vector<BYTE>& pbBlob, const std::vector<BYTE>& IV, const std::string& plaintext, bool usePadding)
{
	auto optEncryption = Encrypt(hAlg, pbBlob, IV, plaintext, usePadding);
	if (not optEncryption)
		return std::nullopt;

	return base64_encode(optEncryption.value().data(), optEncryption.value().size(), false);
}

std::optional<std::string> EasyBCrypt::Decrypt64(BCRYPT_ALG_HANDLE hAlg, const std::vector<BYTE>& pbBlob, const std::vector<BYTE>& IV, const std::string& ciphertext, bool usePadding)
{
	
	std::string ciphertext64 = base64_decode(ciphertext, false);
	auto optDecryption = Decrypt(hAlg, pbBlob, IV, std::vector<BYTE>(ciphertext64.begin(), ciphertext64.end()), usePadding);
	if (not optDecryption)
		return std::nullopt;

	return optDecryption.value();
}

std::optional<EasyBCrypt::derived_key> EasyBCrypt::KeyFromDerivation(BCRYPT_ALG_HANDLE KdfAlgHandle, const std::vector<BYTE>& key, BCryptBufferDesc kdfParameters, size_t aesRounds /*= 128*/)
{
	NTSTATUS status;
	BCRYPT_KEY_HANDLE hKey;
	derived_key dKey;
	ULONG ResultLength;

	status = BCryptGenerateSymmetricKey(
		KdfAlgHandle,														// Algorithm Handle 
		&hKey,																// A pointer to a key handle
		NULL,																// Buffer that recieves the key object;NULL implies memory is allocated and freed by the function
		0,																	// Size of the buffer in bytes
		reinterpret_cast<PBYTE>(const_cast<unsigned char*>(key.data())),	// Buffer that contains the key material
		static_cast<ULONG>(key.size()),										// Size of the buffer in bytes
		0);																	// Flags

	if (not NT_SUCCESS(status))
	{
		ReportError(status);
		return std::nullopt;
	}

	//
	// Derive AES key from the password
	//

	dKey.resize(aesRounds / 8);

	status = BCryptKeyDerivation(
		hKey,											// Handle to the password key
		&kdfParameters,									// Parameters to the KDF algorithm
		reinterpret_cast<PBYTE>(dKey.data()),			// Address of the buffer which receives the derived bytes
		static_cast<ULONG>(dKey.size()),				// Size of the buffer in bytes
		&ResultLength,									// Variable that receives number of bytes copied to above buffer  
		0);												// Flags

	if (not NT_SUCCESS(status))
	{
		ReportError(status);
		BCryptDestroyKey(hKey);
		return std::nullopt;
	}

	return dKey;
}