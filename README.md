# EasyBCrypt
EasyBCrypt is a small wrapper library, written in modern C++ in order to ease the use of AES encryption and Diffie Hellman key exchange with windows api.
<br />


### GenerateRandomBytes
Generate a vector which contains random bytes.
#### Syntax
```
std::varient<STATUS, std::vector<BYTE>> EasyBCrypt::GenerateRandomBytes(
  size_t sz
);
```
#### Parameters
size_t sz - the number of bytes to generate.
#### Return value
Returns a vector that contains the number sz of bytes that indicates the success or STATUS string log that indicates the cause of a failure.


### KeyFromDerivation
Derives a key from a KDF algorithm.
#### Syntax
```
std::varient<STATUS, std::vector<BYTE>> EasyBCrypt::KeyFromDerivation(
  BCRYPT_ALG_HANDLE hKdf,
  const std::vector<BYTE>& key,
  PBCryptBufferDesc kdfParameters,
  WORD rounds /*= 128*/
);
```
#### Parameters
BCRYPT_ALG_HANDLE hAlg - handle for a kdf algorithm <br />
const std::vector\<BYTE>& key - a byte vector that contains the key. <br />
BCryptBufferDesc kdfParameters - struct that contains all the required parameters for a kdf algorithm.
#### Return value
Returns a vector that contains the new key that indicates the success or STATUS string log that indicates the cause of a failure.
#### Remarks
You can use the following algorithm identifiers as the algorithm handle.
* BCRYPT_CAPI_KDF_ALGORITHM
* BCRYPT_SP800108_CTR_HMAC_ALGORITHM
* BCRYPT_SP80056A_CONCAT_ALGORITHM
* BCRYPT_PBKDF2_ALGORITHM

Please refer to https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptkeyderivation
In order to understand BCryptBufferDesc structure and the required parameters.



### CreateSymmetricKeyBlob
Create a key blob to from a symmetric key.
#### Syntax
```
std::varient<STATUS, std::vector<BYTE>> EasyBCrypt::CreateSymmetricKeyBlob(
  BCRYPT_ALG_HANDLE hAlg,
  const std::vector<BYTE>& key,
  ChainingMode mode
);
```
#### Parameters
BCRYPT_ALG_HANDLE hAlg - algorithm handle<br />
const std::vector\<BYTE>& key - a byte vector that contains the key.<br />
ChainingMode mode - AES chaining mode<br />
#### Return value
Returns a vector that contains the key blob that indicates the success or STATUS string log that indicates the cause of a failure.
#### Remarks
You can use one of the following chaining modes
* EasyBCrypt::ChainingMode::CBC	- Sets the algorithm's chaining mode to cipher block chaining.
* EasyBCrypt::ChainingMode::CCM - Sets the algorithm's chaining mode to counter with CBC-MAC mode (CCM).
* EasyBCrypt::ChainingMode::CFB - Sets the algorithm's chaining mode to cipher feedback.
* EasyBCrypt::ChainingMode::ECB - Sets the algorithm's chaining mode to electronic codebook.
* EasyBCrypt::ChainingMode::GCM - Sets the algorithm's chaining mode to Galois/counter mode (GCM).



### CreateAESKeyBlob
CreateAESKeyBlob is a combination of CreateSymmetricKeyBlob and KeyFromDerivation.
We can use this function in order to create a key blob. The benefit of using this function is that there is no need
of opening providers for AES and KDF algorithms.
#### Syntax
```
std::varient<STATUS, std::vactor<BYTE>> EasyBCrypt::CreateAESKeyBlob(
  [out] BCRYPT_ALG_HANDLE& hAlg,
        const std::vector<BYTE>& key,
        const std::wstring& chainingMode,
  [opt] const std::wstring& kdfAlgorithm,
  [opt] PBCryptBufferDesc kdfParameters = nullptr,
        WORD rounds /* = 128 */
);
```
#### Parameters
BCRYPT_ALG_HANDLE& hAlg - uninitialized algorithm handle which<br />
const std::vector\<BYTE>& key - a byte vector that contains the key.<br />
const std::wstring& chainingMode - a reference to chaining mode<br />
const std::wstring& kdfAlgorithm - optional KDF algorithm<br />
PBCryptBufferDesc kdfParameters - optional pointer to a buffer that contains the KDF parameters<br />
WORD rounds - optional rounds that indicates the AES version. such as AES128 or AES192<br />
#### Return value
Returns a vector that contains the key blob that indicates the success or STATUS string log that indicates the cause of a failure.
#### Remarks
If const std::wstring& kdfAlgorithm and PBCryptBufferDesc kdfParameters are passed to the function
then the key is passed through the specified kdf algorithm.



### Encrypt
Encrypt the given plaintext.
#### Syntax
```
std::varient<NTSTATUS, std::vector<BYTE>> EasyBCrypt::Encrypt(
        BCRYPT_ALG_HANDLE hAlg,
        const std::vector<BYTE>& pbBlob,
        const std::vector<BYTE>& IV,
        const std::string& plaintext,
 [opt]  std::vector<BYTE>* authTag /* = nullptr */
);
```
#### Parameters
BCRYPT_ALG_HANDLE hAlg - algorithm handle<br />
const std::vector<BYTE>& pbBlob - key blob to import/export the key<br />
const std::vector<BYTE>& IV - initialization vector<br />
const std::string& plaintext - the plaintext you would like to encrypt<br />
std::vector<BYTE>* authTag - a pointer to initialized vector which the authentication tag will be written<br />
#### Return value
Returns vector of bytes that contains the ciphertext which indicates the success or STATUS string log that indicates the cause of a failure.
#### Remarks
If you choose to use GCM mode you must pass a pointer to a vector. The authentication tag (MAC) is written to this vector which then is used to authenticate
the message.



### Decrypt
Decrypt the given ciphertext
#### Syntax
```
std::varient<STATUS, std::string> EasyBCrypt::Decrypt(
  BCRYPT_ALG_HANDLE hAlg,
        const std::vector<BYTE>& pbBlob,
        const std::vector<BYTE>& IV,
        const std::vector<BYTE>& ciphertext,
 [opt]  std::vector<BYTE>* authTag /* = nullptr */
);
```
#### Parameters
BCRYPT_ALG_HANDLE hAlg - algorithm handle<br />
const std::vector<BYTE>& pbBlob - key blob to import/export the key<br />
const std::vector<BYTE>& IV - initialization vector<br />
const std::string& ciphertext - the cipher you would like to decrypt<br />
std::vector<BYTE>* authTag - a pointer to a vector which contains the authentication tag<br />
#### Return value
Returns string that contains the plaintext which indicates the success or STATUS string log that indicates the cause of a failure.

#### Remarks
If you choose to use GCM mode you must pass a pointer to a vector that contains the authentication tag.



### Encrypt64
Encrypt and encode to base64
#### Syntax
```
std::varient<NTSTATUS, std::string> EasyBCrypt::Encrypt64(
        BCRYPT_ALG_HANDLE hAlg,
        const std::vector<BYTE>& pbBlob,
        const std::vector<BYTE>& IV,
        const std::string& plaintext,
 [opt]  std::vector<BYTE>* authTag /* = nullptr */
);
```
#### Parameters
BCRYPT_ALG_HANDLE hAlg - algorithm handle<br />
const std::vector<BYTE>& pbBlob - key blob to import/export the key<br />
const std::vector<BYTE>& IV - initialization vector<br />
const std::string& plaintext - the cipher you would like to decrypt<br />
std::vector<BYTE>* authTag - a pointer to initialized vector which the authentication tag will be written<br />
#### Return value
Returns string that contains the ciphertext encoded to base64 which indicates the success or STATUS string log that indicates the cause of a failure.

#### Remarks
If you choose to use GCM mode you must pass a pointer to a vector. The authentication tag (MAC) is written to this vector which then is used to authenticate
the message.




### Decrypt64
Decode from base64 and decrypt
#### Syntax
```
std::varient<NTSTATUS, std::string> EasyBCrypt::Decrypt64(
        BCRYPT_ALG_HANDLE hAlg,
        const std::vector<BYTE>& pbBlob,
        const std::vector<BYTE>& IV,
        const std::string& plaintext,
 [opt]  std::vector<BYTE>* authTag /* = nullptr */
);
```
#### Parameters
BCRYPT_ALG_HANDLE hAlg - algorithm handle<br />
const std::vector<BYTE>& pbBlob - key blob to import/export the key<br />
const std::vector<BYTE>& IV - initialization vector<br />
const std::string& ciphertext - the cipher you would like to decrypt<br />
std::vector<BYTE>* authTag - a pointer to a vector which contains the authentication tag<br />
#### Return value
Returns string that contains the plaintext which was decoded from base64 that indicates the success or STATUS string log that indicates the cause of a failure.

#### Remarks
If you choose to use GCM mode you must pass a pointer to a vector that contains the authentication tag.



### CreateDHParamBlob
Create a parameter blob for diffie hellman algorithm
#### Syntax
```
std::shared_ptr<BYTE[]> EasyBCrypt::CreateDHParamBlob(
        DWORD keyLength, /* = 768 */
  [opt] const std::vector<BYTE>& dhPrime,
  [opt] const std::vector<BYTE>& dhGenerator
);
```
#### Parameters
DWORD keyLength - optional key length. The default length is 768 bits<br />
const std::vector<BYTE>& dhPrime - optional prime number. There is a default prime that you can see at the source code.<br />
const std::vector<BYTE>& dhGenerator - optional generator. There is a default prime that you can see at the source code.<br />
#### Return value
Returns shared pointer that contains the DH parameters.
#### Remarks
You can call this function without any arguments which will return the default parameters.



### GenerateDHKeyPair
Generate Diffie Hellman key pair.
#### Syntax
```
std::variant<NTSTATUS, std::vector<BYTE>> EasyBCrypt::GenerateDHKeyPair(
        std::shared_ptr<BYTE[]> dhParams,
  [out] BCRYPT_ALG_HANDLE& exchAlgHandle,
  [out] BCRYPT_KEY_HANDLE& dhKeyHandle
);
```
#### Parameters
std::shared_ptr<BYTE[]> dhParams - The shared pointer to the parameter blob we careted with CreateDHParamBlob function<br />
BCRYPT_ALG_HANDLE& exchAlgHandle - uninitialized algorithm handle<br />
BCRYPT_KEY_HANDLE& dhKeyHandle - uninitialized key handle<br />
#### Return value
Returns vactor that contains the public key blob which indicates a success or status code that indicates the cause of a failure.
#### Remarks
The function returns public key blob which in a real scenario needs to be passed to the server/client.
In addition the function initializes algorithm and key handles.



### GenerateDHSecret
Generate the secret (key) as a result from a DH.
#### Syntax
```
std::variant<NTSTATUS, std::vector<BYTE>> EasyBCrypt::GenerateDHSecret(
        BCRYPT_ALG_HANDLE exchAlgHandle,
        BCRYPT_KEY_HANDLE dhKeyHandle,
        std::vector<BYTE>& alicePubBlob,
 [opt]  const std::wstring& pwszKDF,
 [opt]  PBCryptBufferDesc kdfParameters    
);
```
#### Parameters
BCRYPT_ALG_HANDLE exchAlgHandle - the exchAlgHandle was we passed to GenerateDHKeyPair function.<br />
BCRYPT_KEY_HANDLE& dhKeyHandle - the dhKeyHandle was we passed to GenerateDHKeyPair function.<br />
std::vector<BYTE>& alicePubBlob - the public blob which recivied from the server/client.<br />
const std::wstring& pwszKDF - optional KDF algorithm to use. <br />
PBCryptBufferDesc kdfParameters - optional pointer to a buffer that contains the KDF parameters.<br />
#### Return value
Returns vactor that contains the secret key which indicates a success or status code that indicates the cause of a failure.
#### Remarks
Please refer to https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptderivekey
for additional information about the derivation options.

### EasyCrypt::STATUS
The STATUS string log contains an NTSTATUS code.
Please refer to https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55 <br />
when an error occured.



## Full Client/Server exaple with Diffie Hellman key exchange.

### Server
```
#define WIN32_LEAN_AND_MEAN
#include "../EasyBCrypt/EasyBCrypt.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <format>
#include <memory>
#include <vector>
#pragma comment (lib, "Ws2_32.lib")

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

// buffer to store the shared key
std::vector<BYTE> sharedSecret;

bool OnConnection(SOCKET& sock)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE exchDH = NULL;
	BCRYPT_KEY_HANDLE keyPair = NULL;
	BCryptBufferDesc ParameterList = { 0 };
	BCryptBuffer BufferArray[2] = { 0 };
	BYTE clientHello[32] = { 0 };
	BYTE serverHello[32] = { 0 };
	BYTE seed[64] = { 0 };
	LPCWSTR Label = L"master secret";
	// this is the size of the server public blob.
	std::vector<BYTE> clientPubBlob;
	clientPubBlob.resize(296);

	/* Handshake */

	// generate 32 byte random number
	status = BCryptGenRandom(NULL, &serverHello[0], 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

	if (not NT_SUCCESS(status))
		return false;
	
	// receive client hello message
	if (recv(sock, reinterpret_cast<char*>(clientHello), 32, 0) < 0)
	{
		std::string err = std::format("Error returned from recv. Status code: {:#x}", GetLastError());
		std::cout << err << std::endl;
		return false;
	}

	// send server hello message
	if (send(sock, reinterpret_cast<char*>(serverHello), 32, 0) == INVALID_SOCKET)
	{
		std::string err = std::format("Error returned from send. Status code: {:#x}", GetLastError());
		std::cout << err << std::endl;
		return false;
	}
	
	// merge client and server random numbers
	memcpy(seed, clientHello, 32);
	memcpy(seed + 32, serverHello, 32);

	// KDF parameters
	//specify secret to append
	BufferArray[0].BufferType = KDF_TLS_PRF_SEED;
	BufferArray[0].cbBuffer = sizeof(seed);
	BufferArray[0].pvBuffer = (PVOID)seed;

	//specify secret to perpend
	BufferArray[1].BufferType = KDF_TLS_PRF_LABEL;
	BufferArray[1].cbBuffer = (DWORD)((wcslen(Label) + 1) * sizeof(WCHAR));
	BufferArray[1].pvBuffer = (PVOID)Label;

	ParameterList.cBuffers = 2;
	ParameterList.pBuffers = BufferArray;
	ParameterList.ulVersion = BCRYPTBUFFER_VERSION;

	 //create Diffie Hellman parameter blob
	std::shared_ptr<BYTE[]> paramBlob = EasyBCrypt::CreateDHParamBlob();

	// Generate key pair
	auto optServerPubBlob = EasyBCrypt::GenerateDHKeyPair(paramBlob, exchDH, keyPair);
	if (auto out = std::get_if<EasyBCrypt::STATUS>(&optServerPubBlob))
	{
		std::string err = *(*out);
		std::cout << err << std::endl;
		return false;
	}

	// obtain the server public blob
	std::vector<BYTE> serverPubBlob = std::get<std::vector<BYTE>>(optServerPubBlob);

	// receive client public blob in order to generate the master key
	if (recv(sock, reinterpret_cast<char*>(&clientPubBlob[0]), 296, 0) < 0)
	{
		std::string err = std::format("Error returned from recv. Status code: {:#x}", GetLastError());
		std::cout << err << std::endl;
		return false;
	}

	// send server public blob so the client can generate the master key
	if (send(sock, reinterpret_cast<char*>(&serverPubBlob[0]), 296, 0) == INVALID_SOCKET)
	{
		std::string err = std::format("Error returned from send. Status code: {:#x}", GetLastError());
		std::cout << err << std::endl;
		return false;
	}

	// obtain the shared secret
	auto optSecret = EasyBCrypt::GenerateDHSecret(exchDH, keyPair, clientPubBlob, BCRYPT_KDF_TLS_PRF, &ParameterList);
	if (auto out = std::get_if<EasyBCrypt::STATUS>(&optSecret))
	{
		std::string err = *(*out);
		std::cout << err << std::endl;
		return false;
	}

	// shared secret for both client and server
	sharedSecret = std::get<std::vector<BYTE>>(optSecret);

	return true;
}

bool CreateSocket(SOCKET& serverSocket)
{
	serverSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
	if (serverSocket == INVALID_SOCKET)
	{
		std::string err = std::format("Error returned from WSASocket. Status code: {:#x}", GetLastError());
		std::cerr << err << std::endl;
		return false;
	}

	return true;
}


bool Listen(SOCKET& serverSocket, PCSTR ip, PCSTR port)
{
	PADDRINFOA pinfo;
	ADDRINFOA info;
	ZeroMemory(&info, sizeof(info));
	info.ai_family = AF_INET;
	info.ai_socktype = SOCK_STREAM;
	info.ai_protocol = IPPROTO_TCP;
	info.ai_flags = AI_PASSIVE;

	if (not CreateSocket(serverSocket))
		return false;

	if (getaddrinfo(ip, port, &info, &pinfo) != 0)
	{
		std::string err = std::format("Error returned from getaddrinfo. Status code: {:#x}", GetLastError());
		std::cerr << err << std::endl;
		return false;
	}

	if (bind(serverSocket, pinfo->ai_addr, (int)pinfo->ai_addrlen) == SOCKET_ERROR)
	{
		std::string err = std::format("Error returned from bind. Status code: {:#x}", GetLastError());
		freeaddrinfo(pinfo);
		std::cerr << err << std::endl;
		return false;
	}

	freeaddrinfo(pinfo);

	if (listen(serverSocket, SOMAXCONN) == INVALID_SOCKET)
	{
		std::string err = std::format("Error returned from listen. Status code: {:#x}", GetLastError());
		std::cerr << err << std::endl;
		return false;
	}

	return true;
}

bool Accept(SOCKET& serverSocket, SOCKET& clientSocket)
{
	clientSocket = WSAAccept(serverSocket, NULL, NULL, 0, 0);
	if (clientSocket == INVALID_SOCKET)
	{
		std::string err = std::format("Error returned from WSAAccept. Status code: {:#x}", GetLastError());
		std::cerr << err << std::endl;
		return false;
	}
	bool _onConnection = OnConnection(clientSocket);
	return _onConnection;
}


int main()
{
	//
	WSADATA data;
	SOCKET serverSocket = INVALID_SOCKET;
	SOCKET clientSocket = INVALID_SOCKET;
	BCRYPT_ALG_HANDLE hAlg = NULL;

	// required varients
	std::variant<EasyBCrypt::STATUS, std::vector<BYTE>> optVector;
	std::variant<EasyBCrypt::STATUS, std::string> optString;

	// error status
	EasyBCrypt::STATUS* errorStatus = nullptr;
	std::string errMsg = "";

	// EascyBCrypt buffers 
	std::string secretMessage = "My secret msg.";
	std::string encryptedMessage;
	std::vector<BYTE> keyBlob;
	std::vector<BYTE> nonce;
	std::vector<BYTE> authtag;


	if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
	{
		std::cout << "WSAStartup failed." << std::endl;
		ExitProcess(EXIT_FAILURE);
	}

	if (not Listen(serverSocket, NULL, "4000"))
	{
		goto cleanup;
	}

	if (not Accept(serverSocket, clientSocket))
	{
		goto cleanup;
	}

	// Create symmetric key blob from our shared secret
	optVector = EasyBCrypt::CreateAESKeyBlob(hAlg, sharedSecret, EasyBCrypt::ChaningMode::GCM);
	if (errorStatus = std::get_if<EasyBCrypt::STATUS>(&optVector))
	{
		errMsg = *(*errorStatus);
		goto cleanup;
	}

	// obtain the key blob
	keyBlob = std::get<std::vector<BYTE>>(optVector);

	// generate nonce for GCM mode
	optVector = EasyBCrypt::GenerateRandomBytes(12);
	if (errorStatus = std::get_if<EasyBCrypt::STATUS>(&optVector))
	{
		errMsg = *(*errorStatus);
		goto cleanup;
	}

	// obtain the nonce
	nonce = std::get<std::vector<BYTE>>(optVector);

	// send the nonce in plaintext which is 12 bytes long
	if (send(clientSocket, reinterpret_cast<char*>(&nonce[0]), 12, 0) == INVALID_SOCKET)
	{
		std::string err = std::format("Error returned from send. Status code: {:#x}", GetLastError());
		std::cout << err << std::endl;
		goto cleanup;
	}

	// here we use GCM mode so we pass additional vector to receive the authentication tag
	optString = EasyBCrypt::Encrypt64(hAlg, keyBlob, nonce, secretMessage, &authtag);
	if (errorStatus = std::get_if<EasyBCrypt::STATUS>(&optString))
	{
		errMsg = *(*errorStatus);
		goto cleanup;
	}

	// obtain the encrypted message
	encryptedMessage = std::get<std::string>(optString);

	// sent the authentication tag which is 12 bytes long
	if (send(clientSocket, reinterpret_cast<char*>(&authtag[0]), 12, 0) == INVALID_SOCKET)
	{
		std::string err = std::format("Error returned from send. Status code: {:#x}", GetLastError());
		std::cout << err << std::endl;
		goto cleanup;
	}

	// send the message to the client
	if (send(clientSocket, encryptedMessage.c_str(), encryptedMessage.size(), 0) == INVALID_SOCKET)
	{
		std::string err = std::format("Error returned from send. Status code: {:#x}", GetLastError());
		std::cout << err << std::endl;
		goto cleanup;
	}

	// shutdown the clientSocket so the client side receives 0
	if (shutdown(clientSocket, SD_SEND) == SOCKET_ERROR)
	{
		std::string err = std::format("Error returned from send. Status code: {:#x}", GetLastError());
		std::cout << err << std::endl;
	}

cleanup:
	if (errorStatus)
		std::cout << errMsg << std::endl;

	if (hAlg)
		BCryptCloseAlgorithmProvider(hAlg, 0);

	if (serverSocket)
		closesocket(serverSocket);

	if (clientSocket)
		closesocket(clientSocket);

	WSACleanup();

	std::cin.get();
}
```


### Client
```
#define WIN32_LEAN_AND_MEAN
#include "../EasyBCrypt/EasyBCrypt.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <format>
#include <memory>
#include <vector>
#pragma comment (lib, "Ws2_32.lib")

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

// buffer to store the shared key
std::vector<BYTE> sharedSecret;

bool OnConnection(SOCKET& sock)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE exchDH = NULL;
	BCRYPT_KEY_HANDLE keyPair = NULL;
	BCryptBufferDesc ParameterList = { 0 };
	BCryptBuffer BufferArray[2] = { 0 };
	BYTE clientHello[32] = { 0 };
	BYTE serverHello[32] = { 0 };
	BYTE seed[64] = { 0 };
	LPCWSTR Label = L"master secret";

	// this is the size of the server public blob.
	std::vector<BYTE> serverPubBlob;
	serverPubBlob.resize(296);

	/* Handshake */

	// generate 32 byte random number
	status = BCryptGenRandom(NULL, &clientHello[0], 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);			 

	if (not NT_SUCCESS(status))
		return false;

	// send client hello message
	if (send(sock, reinterpret_cast<char*>(clientHello), 32, 0) == INVALID_SOCKET)
	{
		std::string err = std::format("Error returned from send. Status code: {:#x}", GetLastError());
		std::cout << err << std::endl;
		return false;
	}

	// receive server hello message
	if (recv(sock, reinterpret_cast<char*>(serverHello), 32, 0) < 0)
	{
		std::string err = std::format("Error returned from recv. Status code: {:#x}", GetLastError());
		std::cout << err << std::endl;
		return false;
	}

	// merge client and server random numbers
	memcpy(seed, clientHello, 32);
	memcpy(seed + 32, serverHello, 32);

	// KDF parameters
	//specify secret to append
	BufferArray[0].BufferType = KDF_TLS_PRF_SEED;
	BufferArray[0].cbBuffer = sizeof(seed);
	BufferArray[0].pvBuffer = (PVOID)seed;

	//specify secret to prepend
	BufferArray[1].BufferType = KDF_TLS_PRF_LABEL;
	BufferArray[1].cbBuffer = (DWORD)((wcslen(Label) + 1) * sizeof(WCHAR));
	BufferArray[1].pvBuffer = (PVOID)Label;

	ParameterList.cBuffers = 2;
	ParameterList.pBuffers = BufferArray;
	ParameterList.ulVersion = BCRYPTBUFFER_VERSION;

	// create Diffie Hellman parameter blob
	std::shared_ptr<BYTE[]> paramBlob = EasyBCrypt::CreateDHParamBlob();

	// Generate key pair
	auto optClientPubBlob = EasyBCrypt::GenerateDHKeyPair(paramBlob, exchDH, keyPair);
	if (auto out = std::get_if<EasyBCrypt::STATUS>(&optClientPubBlob))
	{
		std::string err = *(*out);
		std::cout << err << std::endl;
		return false;
	}

	// obtain the client public blob
	std::vector<BYTE> clientPubBlob = std::get<std::vector<BYTE>>(optClientPubBlob);

	// send client public blob so the server can generate the master key
	if (send(sock, reinterpret_cast<char*>(&clientPubBlob[0]), clientPubBlob.size(), 0) == INVALID_SOCKET)
	{
		std::string err = std::format("Error returned from send. Status code: {:#x}", GetLastError());
		std::cout << err << std::endl;
		return false;
	}
		
	// receive server public blob in order to generate the master key
	if (recv(sock, reinterpret_cast<char*>(&serverPubBlob[0]), 296, 0) < 0)
	{
		std::string err = std::format("Error returned from recv. Status code: {:#x}", GetLastError());
		std::cout << err << std::endl;
		return false;
	}

	// obtain the shared secret
	auto optSecret = EasyBCrypt::GenerateDHSecret(exchDH, keyPair, serverPubBlob, BCRYPT_KDF_TLS_PRF, &ParameterList);
	if (auto out = std::get_if<EasyBCrypt::STATUS>(&optSecret))
	{
		std::string err = *(*out);
		std::cout << err << std::endl;
		return false;
	}

	// shared secret for both client and server
	sharedSecret = std::get<std::vector<BYTE>>(optSecret);

	return true;
}

bool CreateSocket(SOCKET& serverSocket)
{
	serverSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
	if (serverSocket == INVALID_SOCKET)
	{
		std::string err = std::format("Error returned from WSASocket. Status code: {:#x}", GetLastError());
		std::cerr << err << std::endl;
		return false;
	}

	return true;
}

bool Connect(SOCKET& serverSocket, PCSTR ip, PCSTR port)
{
	PADDRINFOA result;
	ADDRINFOA filter;
	ZeroMemory(&filter, sizeof(filter));
	filter.ai_family = AF_INET;
	filter.ai_socktype = SOCK_STREAM;
	filter.ai_protocol = IPPROTO_TCP;
	filter.ai_flags = AI_PASSIVE;

	if (getaddrinfo(ip, port, &filter, &result) != 0)
	{
		std::string err = std::format("Error returned from getaddrinfo. Status code: {:#x}", GetLastError());
		std::cerr << err << std::endl;
		return false;
	}

	if (WSAConnect(serverSocket, result->ai_addr, (int)result->ai_addrlen, 0, 0, 0, 0) == SOCKET_ERROR)
	{
		freeaddrinfo(result);
		std::string err = std::format("Error returned from WSAConnect. Status code: {:#x}", GetLastError());
		std::cerr << err << std::endl;
		return false;
	}

	freeaddrinfo(result);
	
	bool _onConnection = OnConnection(serverSocket);
	return _onConnection;
}



int main()
{ 

	// 
	WSADATA data;
	SOCKET serverSocket = INVALID_SOCKET;
	BCRYPT_ALG_HANDLE hAlg = NULL;

	// required varients
	std::variant<EasyBCrypt::STATUS, std::vector<BYTE>> optVector;
	std::variant<EasyBCrypt::STATUS, std::string> optString;

	// error status
	EasyBCrypt::STATUS* errorStatus = nullptr;
	std::string errMsg = "";

	// EascyBCrypt buffers
	std::string messageBuffer = "";
	std::vector<BYTE> nonce(12);
	std::vector<BYTE> authTag(12);
	std::vector<BYTE> keyBlob(296);

	// variables to recevie encrypted message from socket
	char socketBuffer[512] = { 0 };
	int b_recevied = 0;

	if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
	{
		std::cout << "WSAStartup failed." << std::endl;
		return false;
	}

	if (not CreateSocket(serverSocket))
	{
		goto cleanup;
	}

	if (not Connect(serverSocket, "127.0.0.1", "4000"))
	{
		goto cleanup;
	}

	// Create symmetric key blob from our shared secret
	optVector = EasyBCrypt::CreateAESKeyBlob(hAlg, sharedSecret, EasyBCrypt::ChaningMode::GCM);
	if (errorStatus = std::get_if<EasyBCrypt::STATUS>(&optVector))
	{
		errMsg = *(*errorStatus);
		goto cleanup;
	}

	// obtain the key blob
	keyBlob = std::get<std::vector<BYTE>>(optVector);
	
	// receive the nonce which is 12 bytes long
	if (recv(serverSocket, reinterpret_cast<char*>(&nonce[0]), 12, 0) < 0)
	{
		std::string err = std::format("Error returned from recv. Status code: {:#x}", GetLastError());
		std::cout << err << std::endl;
		goto cleanup;
	}

	// receive the authentication tag which is 12 bytes long
	if (recv(serverSocket, reinterpret_cast<char*>(&authTag[0]), 12, 0) < 0)
	{
		std::string err = std::format("Error returned from recv. Status code: {:#x}", GetLastError());
		std::cout << err << std::endl;
		goto cleanup;
	}

	// receive the encrypted message
	while ((b_recevied = recv(serverSocket, socketBuffer, 512, 0)) != 0)
	{
		if (b_recevied < 0)
		{
			std::string err = std::format("Error returned from recv. Status code: {:#x}", GetLastError());
			std::cout << err << std::endl;
			goto cleanup;
		}

		messageBuffer = messageBuffer + socketBuffer;
		ZeroMemory(socketBuffer, 512);
	}

	// decrypt the message. remember to pass the authentication tag
	optString = EasyBCrypt::Decrypt64(hAlg, keyBlob, nonce, messageBuffer, &authTag);
	if (errorStatus = std::get_if<EasyBCrypt::STATUS>(&optString))
	{
		errMsg = errMsg = *(*errorStatus);
		goto cleanup;
	}

	// we can use again the message buffer to obtain the decrypted message
	messageBuffer = std::get<std::string>(optString);

	// display the message
	std::cout << messageBuffer << std::endl;

cleanup:
	if (errorStatus)
		std::cout << errMsg << std::endl;

	if (hAlg)
		BCryptCloseAlgorithmProvider(hAlg, 0);

	if (serverSocket)
		closesocket(serverSocket);

	WSACleanup();

	std::cin.get();
}
```
