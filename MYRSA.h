#include <iostream>
#include <tuple>
#include <cstdint>
#include <stdint.h>
#include <stddef.h>
#include <memory>
#include <cstdio>

#include <cryptopp/algebra.h>
#include <cryptopp/argnames.h>
#include <cryptopp/asn.h>
#include <cryptopp/base64.h>
#include <cryptopp/cryptlib.h> 
#include <cryptopp/elgamal.h> 
#include <cryptopp/eprecomp.h>
#include <cryptopp/filters.h> 
#include <cryptopp/files.h> 
#include <cryptopp/fips140.h>
#include <cryptopp/hex.h> 
#include <cryptopp/integer.h>
#include <cryptopp/modarith.h>
#include <cryptopp/modes.h> 
#include <cryptopp/osrng.h> 
#include <cryptopp/pubkey.h>
#include <cryptopp/queue.h>
#include <cryptopp/rsa.h> 
#include <cryptopp/secblock.h>
#include <cryptopp/smartptr.h>
#include <cryptopp/stdcpp.h>



using namespace std;
using namespace CryptoPP;

#define MAXLINE 100
#define MAX_PATH_LEN 100
#define MAX_MSG_LEN 100
#define DEBUG_FILES 0
#define DEUBG_PART 0
#define DEBUG_MAIN 1
#define DEBUG_PRINT 1

enum PADDING {
	_PKCS1v15,
	_OAEP
};

class MYRSA {
public:
	AutoSeededRandomPool rng;
	MYRSA();
	MYRSA(char* pubKeyFile, char* priKeyFile);
	~MYRSA();
	void SetPublibKey(char* pubKeyFile);
	void SetPrivateKey(char* priKeyFile);
	void Encryption(char* plainPath,char* cipherPath);
	void Decryption(char* plainPath, char* cipherPath);
	void Sign(char* signMsg, char* signOutPath);
	bool VerifySign(char* vsignPath);
	void RSAEnc(uint8_t* Data, size_t Size);
	void RSASignPKCS(char* Data, size_t Size);
private:
	int keySize;
	int CipherSize;
	RSA::PrivateKey privKey;
	RSA::PublicKey pubKey;
};

string Uint8_t2HexString(uint8_t in);
uint8_t HexString2Uint8_t(char c1, char c2);
void compare(uint8_t* a, uint8_t* b, size_t Size);
void hexdump(void* ptr, int buflen);
void showParam(InvertibleRSAFunction params);


