#include "EBcrypt.h"

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
		(PBYTE)&cbHashObject,
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
		(PBYTE)&cbHash,
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
		(PBYTE)bytes,
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

std::optional<std::vector<BYTE>> EasyBCrypt::Hash(string& str)
{
	auto optHash = Hash(reinterpret_cast<BYTE*>(str.data()), static_cast<DWORD>(str.size()));
	if (not optHash) return nullopt;

	return optHash.value();
}

std::optional<std::vector<BYTE> > EasyBCrypt::GenerateIV(BCRYPT_ALG_HANDLE hAlg)
{
	NTSTATUS status;
	DWORD blockLength;
	DWORD res;
	std::vector<BYTE> IV;

	status = BCryptGetProperty(
		hAlg,							// Handle to a CNG object
		BCRYPT_BLOCK_LENGTH,      // Property name (null terminated unicode string)
		(PBYTE)&blockLength,        // Addr of the output buffer which recieves the property value
		sizeof(blockLength),        // Size of the buffer in the bytes
		&res,					   // Number of bytes that were copied into the buffer
		0);                         // Flags

	if (not NT_SUCCESS(status))
		return nullopt;

	IV.resize(blockLength);

	status = BCryptGenRandom(
		NULL,                          // Alg Handle pointer; If NULL, the default provider is chosen
		(PBYTE)IV.data(),                // Address of the buffer that recieves the random number(s)
		blockLength,                     // Size of the buffer in bytes
		BCRYPT_USE_SYSTEM_PREFERRED_RNG); // Flags 

	if (not NT_SUCCESS(status))
		return nullopt;

	return IV;
}

std::optional<std::vector<BYTE>> EasyBCrypt::GenerateSymmetricKeyHandle(BCRYPT_ALG_HANDLE hAlg, std::vector<BYTE> key, const std::wstring& chainingMode)
{
	NTSTATUS status;
	BCRYPT_KEY_HANDLE hKey;
	std::vector<BYTE> pbBlob;
	DWORD cbBlob;
	DWORD chainingModeLength = (chainingMode.size() + 1) * sizeof(wchar_t);

	status = BCryptGenerateSymmetricKey(
		hAlg,						// Algorithm provider handle
		&hKey,							// A pointer to key handle
		NULL,                     // A pointer to the buffer that recieves the key object;NULL implies memory is allocated and freed by the function
		0,                        // Size of the buffer in bytes
		(PBYTE)key.data(),          // A pointer to a buffer that contains the key material
		(DWORD)key.size(),          // Size of the buffer in bytes
		0);                         // Flags

	if (not NT_SUCCESS(status))
		return std::nullopt;

	status = BCryptSetProperty(
		hKey,							  // Handle to a CNG object          
		BCRYPT_CHAINING_MODE,       // Property name(null terminated unicode string)
		(PBYTE)chainingMode.data(),    // Address of the buffer that contains the new property value 
		chainingModeLength,            // Size of the buffer in bytes
		0);							 // Flags

	if (not NT_SUCCESS(status))
		return std::nullopt;

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
		return std::nullopt;

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
		return std::nullopt;

	status = BCryptDestroyKey(hKey);
		
	if (not NT_SUCCESS(status))
		return std::nullopt;

	return pbBlob;
}

std::optional<std::vector<BYTE>> EasyBCrypt::Encrypt(BCRYPT_ALG_HANDLE hAlg, std::vector<BYTE> pbBlob, std::vector<BYTE> IV, std::string plaintext)
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
		pbBlob.data(),
		(ULONG)pbBlob.size(),
		0);

	if (not NT_SUCCESS(status))
		return std::nullopt;

	memcpy(PTRtmpIV, IV.data(), IV.size());

	status = BCryptEncrypt(
		hKey,									// Handle to a key which is used to encrypt 
		(PBYTE)plaintext.data(),         // Address of the buffer that contains the plaintext
		(ULONG)plaintext.size(),         // Size of the buffer in bytes
		NULL,                        // A pointer to padding info, used with asymmetric and authenticated encryption; else set to NULL
		PTRtmpIV,						   // Address of the buffer that contains the IV. 
		(ULONG)IV.size(),				   // Size of the IV buffer in bytes
		NULL,						   // Address of the buffer the recieves the ciphertext
		0,                             // Size of the buffer in bytes
		&CipherTextLength,            // Variable that recieves number of bytes copied to ciphertext buffer 
		BCRYPT_BLOCK_PADDING);         // Flags; Block padding allows to pad data to the next block size

	if (not NT_SUCCESS(status))
		return nullopt;

	enc.resize(CipherTextLength);

	status = BCryptEncrypt(
		hKey,									 // Handle to a key which is used to encrypt 
		(PBYTE)plaintext.data(),          // Address of the buffer that contains the plaintext
		(ULONG)plaintext.size(),          // Size of the buffer in bytes
		NULL,                         // A pointer to padding info, used with asymmetric and authenticated encryption; else set to NULL
		PTRtmpIV,                           // Address of the buffer that contains the IV. 
		(ULONG)IV.size(),                   // Size of the IV buffer in bytes
		(PBYTE)enc.data(),               // Address of the buffer the recieves the ciphertext
		CipherTextLength,				// Size of the buffer in bytes
		&res,							// Variable that recieves number of bytes copied to ciphertext buffer 
		BCRYPT_BLOCK_PADDING);			// Flags; Block padding allows to pad data to the next block size

	if (not NT_SUCCESS(status))
		return nullopt;

	return enc;
}

std::optional<std::string> EasyBCrypt::Decrypt(BCRYPT_ALG_HANDLE hAlg, std::vector<BYTE> pbBlob, std::vector<BYTE> IV, std::vector<BYTE> ciphertext)
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
		pbBlob.data(),
		(ULONG)pbBlob.size(),
		0);

	if (not NT_SUCCESS(status))
		return std::nullopt;

	memcpy(PTRtmpIV, IV.data(), IV.size());

	status = BCryptDecrypt(
		hKey,								// Handle to a key which is used to encrypt 
		ciphertext.data(),			// Address of the buffer that contains the ciphertext
		(ULONG)ciphertext.size(),    // Size of the buffer in bytes
		NULL,					   // A pointer to padding info, used with asymmetric and authenticated encryption; else set to NULL
		PTRtmpIV,					   // Address of the buffer that contains the IV. 
		(ULONG)IV.size(),			   // Size of the IV buffer in bytes
		NULL,					   // Address of the buffer the recieves the plaintext
		0,						   // Size of the buffer in bytes
		&plaintextLength,		   // Variable that recieves number of bytes copied to plaintext buffer 
		BCRYPT_BLOCK_PADDING);

	if (not NT_SUCCESS(status))
	{
		ReportError(status);
		return nullopt;
	}
		
	dec.resize(plaintextLength);

	status = BCryptDecrypt(
		hKey,									// Handle to a key which is used to encrypt 
		(PBYTE)ciphertext.data(),        // Address of the buffer that contains the ciphertext
		(ULONG)ciphertext.size(),        // Size of the buffer in bytes
		NULL,                        // A pointer to padding info, used with asymmetric and authenticated encryption; else set to NULL
		PTRtmpIV,                          // Address of the buffer that contains the IV. 
		(ULONG)IV.size(),                  // Size of the IV buffer in bytes
		(PBYTE)dec.data(),              // Address of the buffer the recieves the plaintext
		plaintextLength,                // Size of the buffer in bytes
		&res,                          // Variable that recieves number of bytes copied to plaintext buffer 
		BCRYPT_BLOCK_PADDING);

	if (not NT_SUCCESS(status))
	{
		ReportError(status);
		return nullopt;
	}

	status = BCryptDestroyKey(hKey);

	if (not NT_SUCCESS(status))
		return std::nullopt;

	dec.resize(res);
	dec.shrink_to_fit();

	return dec;
}

std::optional<std::string> EasyBCrypt::Encrypt64(BCRYPT_ALG_HANDLE hAlg, std::vector<BYTE> pbBlob, std::vector<BYTE> IV, std::string plaintext)
{
	auto optEncryption = Encrypt(hAlg, pbBlob, IV, plaintext);
	if (not optEncryption)
		return std::nullopt;

	return base64_encode(optEncryption.value().data(), optEncryption.value().size(), false);
}

std::optional<std::string> EasyBCrypt::Decrypt64(BCRYPT_ALG_HANDLE hAlg, std::vector<BYTE> pbBlob, std::vector<BYTE> IV, std::string ciphertext)
{
	
	ciphertext = base64_decode(ciphertext, false);
	auto optDecryption = Decrypt(hAlg, pbBlob, IV, std::vector<BYTE>(ciphertext.begin(), ciphertext.end()));
	if (not optDecryption)
		return std::nullopt;

	return optDecryption.value();
}

