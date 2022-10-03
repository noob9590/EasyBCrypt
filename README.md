# EasyBCrypt
EasyBCrypt is a small wrapper library, written in modern C++ in order to ease the use of AES and Diffie Hellman encryptions with windows api.
<br />


### GenerateIV
Generates random initialization vector or based on the chosen chaining mode.
The user also may specify the size of the IV/nonce by passing it to the function.
#### Syntax
```
std::varient<NTSTATUS, std::vector<BYTE>> EasyBCrypt::GenerateIV(
  const std::wstring& chainingMode, DWORD IVSize
);
```
#### Parameters
const std::wstring& chaningMode - optional chaining mode 
DWORD IVSize - optional vector size
#### Return value
Returns a vector that contains the initialization vector that indicates the success or status code that indicates the cause of a failure.
#### Remarks
If the user does not specify any size, the default size for AES-CBC and AES-CFB is 16 and the default size for AES-GCM and AES-CCM is 12.



### KeyFromDerivation
Derives a key from a KDF algorithm.
#### Syntax
```
std::varient<NTSTATUS, std::vector<BYTE>> EasyBCrypt::KeyFromDerivation(
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
Returns a vector that contains the new key that indicates the success or status code that indicates the cause of a failure.
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
std::varient<NTSTATUS, std::vector<BYTE>> EasyBCrypt::CreateSymmetricKeyBlob(
  BCRYPT_ALG_HANDLE hAlg,
  const std::vector<BYTE>& key,
  const std::wstring& chainingMode
);
```
#### Parameters
BCRYPT_ALG_HANDLE hAlg - algorithm handle<br />
const std::vector\<BYTE>& key - a byte vector that contains the key.<br />
const std::wstring& chainingMode - a reference to chaining mode<br />
#### Return value
Returns a vector that contains the key blob that indicates the success or status code that indicates the cause of a failure.
#### Remarks
You can use one of the following chaining modes
* BCRYPT_CHAIN_MODE_CBC	- Sets the algorithm's chaining mode to cipher block chaining.
* BCRYPT_CHAIN_MODE_CCM - Sets the algorithm's chaining mode to counter with CBC-MAC mode (CCM).
* BCRYPT_CHAIN_MODE_CFB - Sets the algorithm's chaining mode to cipher feedback.
* BCRYPT_CHAIN_MODE_ECB - Sets the algorithm's chaining mode to electronic codebook.
* BCRYPT_CHAIN_MODE_GCM - Sets the algorithm's chaining mode to Galois/counter mode (GCM).



### CreateAESKeyBlob
CreateAESKeyBlob is a combination of CreateSymmetricKeyBlob and KeyFromDerivation.
We can use this function in order to create a key blob. The benefit of using this function is that there is no need
of opening providers for AES and KDF algorithms.
#### Syntax
```
std::varient<NTSTATUS, std::vactor<BYTE>> EasyBCrypt::CreateAESKeyBlob(
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
Returns a vector that contains the key blob that indicates the success or status code that indicates the cause of a failure.
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
  bool usePadding /* = true */
);
```
#### Parameters
BCRYPT_ALG_HANDLE hAlg - algorithm handle<br />
const std::vector<BYTE>& pbBlob - key blob to import/export the key<br />
const std::vector<BYTE>& IV - initialization vector<br />
const std::string& plaintext - the plaintext you would like to encrypt<br />
bool usePadding - padding for a block cipher<br />
#### Return value
Returns vector of bytes that contains the ciphertext which indicates the success or status code that indicates the cause of a failure.
#### Remarks
If you choose to use GCM mode or CCM mode then set padding to false.



### Decrypt
Decrypt the given ciphertext
#### Syntax
```
std::varient<NTSTATUS, std::string> EasyBCrypt::Decrypt(
  BCRYPT_ALG_HANDLE hAlg,
  const std::vector<BYTE>& pbBlob,
  const std::vector<BYTE>& IV,
  const std::vector<BYTE>& ciphertext,
  bool usePadding /* = true */
);
```
#### Parameters
BCRYPT_ALG_HANDLE hAlg - algorithm handle<br />
const std::vector<BYTE>& pbBlob - key blob to import/export the key<br />
const std::vector<BYTE>& IV - initialization vector<br />
const std::string& ciphertext - the cipher you would like to decrypt<br />
bool usePadding - padding for a block cipher<br />
#### Return value
Returns string that contains the plaintext which indicates the success or status code that indicates the cause of a failure.

#### Remarks
If you choose to use GCM mode or CCM mode then set padding to false.



### Encrypt64
Encrypt and encode to base64
#### Syntax
```
std::varient<NTSTATUS, std::string> EasyBCrypt::Encrypt64(
  BCRYPT_ALG_HANDLE hAlg,
  const std::vector<BYTE>& pbBlob,
  const std::vector<BYTE>& IV,
  const std::string& plaintext,
  bool usePadding /* = true */
);
```
#### Parameters
BCRYPT_ALG_HANDLE hAlg - algorithm handle<br />
const std::vector<BYTE>& pbBlob - key blob to import/export the key<br />
const std::vector<BYTE>& IV - initialization vector<br />
const std::string& plaintext - the cipher you would like to decrypt<br />
bool usePadding - padding for a block cipher<br />
#### Return value
Returns string that contains the ciphertext encoded to base64 which indicates the success or status code that indicates the cause of a failure.

#### Remarks
If you choose to use GCM mode or CCM mode then set padding to false.




### Decrypt64
Decode from base64 and decrypt
#### Syntax
```
std::varient<NTSTATUS, std::string> EasyBCrypt::Decrypt64(
  BCRYPT_ALG_HANDLE hAlg,
  const std::vector<BYTE>& pbBlob,
  const std::vector<BYTE>& IV,
  const std::string& plaintext,
  bool usePadding /* = true */
);
```
#### Parameters
BCRYPT_ALG_HANDLE hAlg - algorithm handle<br />
const std::vector<BYTE>& pbBlob - key blob to import/export the key<br />
const std::vector<BYTE>& IV - initialization vector<br />
const std::string& ciphertext - the cipher you would like to decrypt<br />
bool usePadding - padding for a block cipher<br />
#### Return value
Returns string that contains the plaintext which was decoded from base64 that indicates the success or status code that indicates the cause of a failure.

#### Remarks
If you choose to use GCM mode or CCM mode then set padding to false.



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
