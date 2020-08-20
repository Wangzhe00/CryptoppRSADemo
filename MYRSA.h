#include <iostream>
#include <tuple>
#include <cstdint>
#include <stdint.h>
#include <stddef.h>
#include <memory>
#include <cstdio>

#include <cryptopp/cryptlib.h> 
#include <cryptopp/filters.h> 
#include <cryptopp/files.h> 
#include <cryptopp/modes.h> 
#include <cryptopp/hex.h> 
#include <cryptopp/rsa.h> 
#include <cryptopp/osrng.h> 
#include <cryptopp/elgamal.h> 
#include <cryptopp/base64.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/integer.h>
#include <cryptopp/secblock.h>
#include <cryptopp/queue.h>
#include <cryptopp/asn.h>


using namespace std;
using namespace CryptoPP;

#define MAXLINE 100
#define DEBUG_FILES 0
#define DEUBG_PART 0
#define DEBUG_MAIN 1
#define DEBUG_PRINT 1

class MYRSA {
public:
	int keySize;
	int CipherSize;
	RSA::PrivateKey privKey;
	RSA::PublicKey pubKey;
	MYRSA();
	MYRSA(size_t* Size);
	MYRSA(char* pubKeyFile, char* priKeyFile);
	~MYRSA();
	void SetPublibKey(char* pubKeyFile);
	void SetPrivateKey(char* priKeyFile);
	void Encryption(char* plainPath,char* cipherPath);
	void Decryption(char* plainPath, char* cipherPath);
	void Sign(char* signMsg, char* signOutPath);
	bool VerifySign(char* vsignPath);
	void RSAEncOAEP(uint8_t* Data, size_t Size);
	void RSASignPKCS(uint8_t* Data, size_t Size);
	void Run(uint8_t* Data, size_t Size);
};

void compare(uint8_t* a, uint8_t* b, size_t Size);
void hexdump(void* ptr, int buflen);
void showParam(InvertibleRSAFunction params);


enum PADDING {
	_PKCS1v15,
	_OAEP
};


