# EasyBCrypt
EasyBCrypt is a small wrapper library, written in modern C++ in order to ease the use of AES encryption with windows api.
<br />


### GenerateIV
Generates random initialization vector with the same size as AES block length.
#### Syntax
```
std::optional<std::vector<BYTE>> EasyBCrypt::GenerateIV(
  BCRYPT_ALG_HANDLE hAlg
);
```
#### Parameters
BCRYPT_ALG_HANDLE - algorithm handle
#### Return value
Vector of bytes.
#### Remarks
Use this function only after you already opened an algorithm provider.
<br /> For additional information please refer to <br />
https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider



### KeyFromDerivation
Derives a key from a KDF algorithm.
#### Syntax
```
std::optional<std::vector<BYTE>> EasyBCrypt::KeyFromDerivation(
  BCRYPT_ALG_HANDLE hKdf,
  const std::vector<BYTE>& key,
  BCryptBufferDesc kdfParameters,
  size_t aesRounds /*= 128*/
);
```
#### Parameters
BCRYPT_ALG_HANDLE hAlg - handle for a kdf algorithm <br />
const std::vector\<BYTE>& key - a byte vector that contains the key. <br />
BCryptBufferDesc kdfParameters - struct that contains all the required parameters for a kdf algorithm.
#### Return value
vector that contains the new key.
#### Remarks
You can use the following algorithm identifiers as the algorithm handle.
* BCRYPT_CAPI_KDF_ALGORITHM
* BCRYPT_SP800108_CTR_HMAC_ALGORITHM
* BCRYPT_SP80056A_CONCAT_ALGORITHM
* BCRYPT_PBKDF2_ALGORITHM

Please refer to https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptkeyderivation
In order to understand BCryptBufferDesc structure and the required parameters.



### GenerateKeyBlob
Generates a key blob to import/export the key when we encrypt/decrypt.
#### Syntax
```
std::optional<std::vector<BYTE>> EasyBCrypt::GenerateKeyBlob(
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
vector of bytes that contains the key blob.
#### Remarks
You can use one of the following chaining modes
* BCRYPT_CHAIN_MODE_CBC	- Sets the algorithm's chaining mode to cipher block chaining.
* BCRYPT_CHAIN_MODE_CCM - Sets the algorithm's chaining mode to counter with CBC-MAC mode (CCM).
* BCRYPT_CHAIN_MODE_CFB - Sets the algorithm's chaining mode to cipher feedback.
* BCRYPT_CHAIN_MODE_ECB - Sets the algorithm's chaining mode to electronic codebook.
* BCRYPT_CHAIN_MODE_GCM - Sets the algorithm's chaining mode to Galois/counter mode (GCM).



### Encrypt
Encrypt the given plaintext.
#### Syntax
```
std::optional<std::vector<BYTE>> EasyBCrypt::Encrypt(
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
vector of bytes that contains the ciphertext.
#### Remarks
If you choose to use GCM mode or CCM mode then set padding to false.



### Decrypt
Decrypt the given ciphertext
#### Syntax
```
std::optional<std::vector<BYTE>> EasyBCrypt::Decrypt(
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
string that contains the plaintext.
#### Remarks
If you choose to use GCM mode or CCM mode then set padding to false.



### Encrypt64
Encrypt and encode to base64
#### Syntax
```
std::optional<std::string> EasyBCrypt::Encrypt64(
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
string that contains the plaintext.
#### Remarks
If you choose to use GCM mode or CCM mode then set padding to false.




### Decrypt64
Decode from base64 and decrypt
#### Syntax
```
std::optional<std::string> EasyBCrypt::Decrypt64(
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
string that contains the plaintext.
#### Remarks
If you choose to use GCM mode or CCM mode then set padding to false.
