#include "RSAKeyPair.h"

using namespace std;
using namespace CryptoPP;

#define MAXLINE 100
#define COMPARE(a, b, x) x += (a - b)
#define DEBUG 1

extern PADDING padding;

MYRSA::MYRSA() {

}

MYRSA::MYRSA(size_t* Size) {
	if (*Size > 86) {
		keySize = 2048;
		CipherSize = 256;
		if (*Size > 214)
			*Size = 214;
	}
	else {
		keySize = 1024;
		CipherSize = 128;
	}
	// Generate Parameters
	AutoSeededRandomPool rng;
	InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize(rng, keySize);

	// Create Keys
	RSA::PrivateKey privateKey(params);
	RSA::PublicKey publicKey(params);

	privKey = privateKey;
	pubKey = publicKey;

	showParam(params);
}

MYRSA::MYRSA(char* pubKeyFile, char* priKeyFile) {
	ifstream RSAPublicFile, RSAPrivateFile;
	RSAPublicFile.open(pubKeyFile, ios::in);
	RSAPrivateFile.open(priKeyFile, ios::in);

	if (!RSAPublicFile || !RSAPrivateFile) {
		/* check your file name */
		cout << "failed open... maybe the file name is wrong..\n";
	}
	string tmp[MAXLINE], tmp1[MAXLINE];
	string RSAPublicKey, RSAPrivateKey;
	int cur = 0;
	while (getline(RSAPublicFile, tmp[cur++]));
	// keey only the key part, remove the header and footer. 
	for (int i = 1; i < cur - 2; ++i) {
		RSAPublicKey += tmp[i] + "\n";
	}
	//cout << RSAPublicKey << endl;
	// clear tempporary variables.
	cur = 0;

	while (getline(RSAPrivateFile, tmp1[cur++]));
	// keey only the key part, remove the header and footer. 
	for (int i = 1; i < cur - 2; ++i) {
		RSAPrivateKey += tmp1[i] + "\n";
	}
	//cout << RSAPrivateKey << endl;
	RSAPublicFile.close();
	RSAPrivateFile.close();

	ByteQueue pubQueue, priQueue;
	Base64Decoder pubDecoder, priDecoder;
	pubDecoder.Attach(new Redirector(pubQueue));
	pubDecoder.Put((const byte*)RSAPublicKey.data(), RSAPublicKey.length());
	pubDecoder.MessageEnd();

	priDecoder.Attach(new Redirector(priQueue));
	priDecoder.Put((const byte*)RSAPrivateKey.data(), RSAPrivateKey.length());
	priDecoder.MessageEnd();

	pubKey.BERDecode(pubQueue);
	privKey.BERDecode(priQueue);

	RSAFunction pubParams;
	InvertibleRSAFunction priParams;
	pubParams.Initialize(pubKey.GetModulus(), pubKey.GetPublicExponent());
	priParams.Initialize(privKey.GetModulus(), privKey.GetPublicExponent(), privKey.GetPrivateExponent());
	
	Integer wz = pubKey.GetModulus();
	cout << wz.BitCount() << endl;
	keySize = pubKey.GetModulus().BitCount();
	CipherSize = keySize > 2000 ? 256 : 128;

	cout << "pub N: " << pubKey.GetModulus() << endl;
	cout << "pub E: " << pubKey.GetPublicExponent() << endl << endl;
	cout << "pri N: " << privKey.GetModulus() << endl;
	cout << "pri E: " << privKey.GetPublicExponent() << endl;
	cout << "pri D: " << privKey.GetPrivateExponent() << endl;

	// Create Keys
	RSA::PublicKey publicKey(pubParams);
	RSA::PrivateKey privateKey(priParams);

	privKey = privateKey;
	pubKey = publicKey;
}

MYRSA::~MYRSA() {
	std::cout << "ALL DONE!!" << endl;
}

void MYRSA::SetPublibKey(char* pubKeyFile) {
	ifstream RSAPublicFile;
	RSAPublicFile.open(pubKeyFile, ios::in);

	if (!RSAPublicFile) {
		/* check your file name */
		cout << "failed open... maybe the file name is wrong..\n";
	}
	string tmp[MAXLINE];
	string RSAPublicKey;
	int cur = 0;
	while (getline(RSAPublicFile, tmp[cur++]));
	// keey only the key part, remove the header and footer. 
	int EOE = tmp[cur - 1] == "";
	for (int i = 1; i < cur - 1 - EOE; ++i) {
		RSAPublicKey += tmp[i] + "\n";
	}

	RSAPublicFile.close();

	ByteQueue pubQueue;
	Base64Decoder pubDecoder;
	pubDecoder.Attach(new Redirector(pubQueue));
	pubDecoder.Put((const byte*)RSAPublicKey.data(), RSAPublicKey.length());
	pubDecoder.MessageEnd();


	pubKey.BERDecode(pubQueue);

	RSAFunction pubParams;
	pubParams.Initialize(pubKey.GetModulus(), pubKey.GetPublicExponent());

	Integer wz = pubKey.GetModulus();
	cout << wz.BitCount() << endl;
	keySize = pubKey.GetModulus().BitCount();
	CipherSize = keySize > 2000 ? 256 : 128;

	cout << "pub N: " << pubKey.GetModulus() << endl;
	cout << "pub E: " << pubKey.GetPublicExponent() << endl << endl;

	// Create Keys
	RSA::PublicKey publicKey(pubParams);

	pubKey = publicKey;
}

void MYRSA::SetPrivateKey(char* priKeyFile) {
	ifstream RSAPrivateFile;
	RSAPrivateFile.open(priKeyFile, ios::in);

	if (!RSAPrivateFile) {
		/* check your file name */
		cout << "failed open... maybe the file name is wrong..\n";
	}
	string tmp1[MAXLINE];
	string RSAPrivateKey;
	int cur = 0;

	while (getline(RSAPrivateFile, tmp1[cur++]));

	// keey only the key part, remove the header and footer. 
	int EOE = tmp1[cur - 1] == "\n";
	for (int i = 1; i < cur - 1 - EOE; ++i) {
		RSAPrivateKey += tmp1[i] + "\n";
	}
	//cout << RSAPrivateKey << endl;
	RSAPrivateFile.close();

	ByteQueue priQueue;
	Base64Decoder priDecoder;

	priDecoder.Attach(new Redirector(priQueue));
	priDecoder.Put((const byte*)RSAPrivateKey.data(), RSAPrivateKey.length());
	priDecoder.MessageEnd();

	privKey.BERDecode(priQueue);

	InvertibleRSAFunction priParams;
	priParams.Initialize(privKey.GetModulus(), privKey.GetPublicExponent(), privKey.GetPrivateExponent());

	Integer wz = privKey.GetModulus();
	cout << wz.BitCount() << endl;
	keySize = privKey.GetModulus().BitCount();
	CipherSize = keySize > 2000 ? 256 : 128;

	cout << "pri N: " << privKey.GetModulus() << endl;
	cout << "pri E: " << privKey.GetPublicExponent() << endl;
	cout << "pri D: " << privKey.GetPrivateExponent() << endl;

	// Create Keys
	RSA::PrivateKey privateKey(priParams);

	privKey = privateKey;
}

string Uint8_t2HexString(uint8_t in) {
	string res = "";
	uint16_t _in = (uint16_t)in;
	res += (_in / 16 > 9) ? ('A' + _in / 16 - 10) : ('0' + _in / 16);
	res += (_in % 16 > 9) ? ('A' + _in % 16 - 10) : ('0' + _in % 16);
	return res;
}

void MYRSA::Encryption(char* plainPath, char* cipherPath) {
	ifstream plainFile;
	ofstream cipherFile;
	plainFile.open(plainPath, ios::in);
	cipherFile.open(cipherPath, ios::out);

	string tmp[MAXLINE];
	string data;
	int cur = 0, len = 0;
	while (getline(plainFile, tmp[cur])) {
		len += tmp[cur].size();
		data += tmp[cur++];
	}

	AutoSeededRandomPool rng;

	switch (padding) {
		case _PKCS1v15: {
			RSAES_PKCS1v15_Encryptor e(pubKey);

			int seedLen = keySize / 8 - 11;
			uint8_t* cipher = (uint8_t*)malloc(CipherSize);
			string justTest;

			for (int st = 0; st < data.size(); st += seedLen) {
				int realLen = min(seedLen, (int)(data.size() - st));
				uint8_t* plain = (uint8_t*)malloc(realLen);
				for (int i = st; i < st + realLen; ++i) {
					plain[i - st] = data[i];
				}
				ArraySource ss1(plain, realLen, true,
					new PK_EncryptorFilter(rng, e,
						new ArraySink(cipher, CipherSize)));
				for (int i = 0; i < CipherSize; ++i) {
					string t = Uint8_t2HexString(cipher[i]);
					cipherFile << t;
					justTest += t;
				}puts("");
#if DEBUG_PRINT
				std::cout << "    ===============================================\n";
				std::cout << "[*] DEBUG : _PKCS1v15()" << endl;
				std::cout << "    keySize  : " << keySize << endl;
				std::cout << "    CipherSize : " << CipherSize << endl;
				std::cout << "    Size     : " << realLen << endl;
				std::cout << "[*] Plain  : " << endl;
				hexdump(plain, realLen);
				std::cout << "[*] Cipher  : " << endl;
				hexdump(cipher, CipherSize);
				std::cout << "[*] justTest  : " << endl;
				std::cout << "   " << justTest << endl;
#endif // DEBUG_PRINT

			}
			break;
		}
		case _OAEP: {

			RSAES_OAEP_SHA_Encryptor e(pubKey);

			int seedLen = keySize / 8 - 42;
			uint8_t* cipher = (uint8_t*)malloc(CipherSize);

			for (int st = 0; st < data.size(); st += seedLen) {
				int realLen = min(seedLen, (int)(data.size() - st));
				uint8_t* plain = (uint8_t*)malloc(realLen);
				for (int i = st; i < st + realLen; ++i) {
					plain[i - st] = data[i];
				}

				ArraySource ss1(plain, realLen, true,
					new PK_EncryptorFilter(rng, e,
						new ArraySink(cipher, CipherSize)));
				for (int i = 0; i < CipherSize; ++i) {
					cipherFile << cipher[i];
				}


			}
			break;
		}
		default: {
			break;
		}
	}
	plainFile.close();
	cipherFile.close();
}

void MYRSA::Decryption(char* cipherPath, char* recoverPath) {
	ifstream cipherFile;
	ofstream recoverFile;
	cipherFile.open(cipherPath, ios::in);
	recoverFile.open(recoverPath, ios::out);


	uint8_t data[1000];

	int len = 0;
	uint8_t tmp;
	while (cipherFile >> tmp) {
		data[len++] = tmp;
	}

#if DEBUG_PRINT
	std::cout << "    ===============================================\n";
	std::cout << "    keySize  : " << keySize << endl;
	std::cout << "    CipherSize : " << CipherSize << endl;
	std::cout << "    Size     : " << len << endl;
	std::cout << "[*] Cipher  : " << endl;
	hexdump(data, CipherSize);
#endif // DEBUG_PRINT

	AutoSeededRandomPool rng;

	switch (padding) {
		case _PKCS1v15: {
			_ASSERT(len % CipherSize == 0);

			RSAES_PKCS1v15_Decryptor d(privKey);

			int roundNum = len / CipherSize;
			int receiveLen = keySize / 8 - 11;

			uint8_t* cipher = (uint8_t*)malloc(CipherSize);
			uint8_t* recover = (uint8_t*)malloc(receiveLen);
			for (int st = 0; st < roundNum; ++st) {
				for (int i = 0; i < CipherSize; ++i) {
					cipher[i] = (int)(data[st * CipherSize + i]);
				}
				ArraySource ss2(cipher, CipherSize, true,
					new PK_DecryptorFilter(rng, d,
						new ArraySink(recover, receiveLen)));
				for (int i = 0; i < receiveLen; ++i) {
					recoverFile << recover[i];
				}
			}
			break;
		}
		case _OAEP: {

			_ASSERT(len % CipherSize == 0);

			RSAES_OAEP_SHA_Decryptor d(privKey);

			int roundNum = len / CipherSize;
			int receiveLen = keySize / 8 - 42;

			uint8_t* cipher = (uint8_t*)malloc(CipherSize);
			uint8_t* recover = (uint8_t*)malloc(receiveLen);

			for (int st = 0; st < roundNum; ++st) {
				uint8_t* cipher = (uint8_t*)malloc(CipherSize);
				for (int i = 0; i < CipherSize; ++i) {
					cipher[i] = data[st * CipherSize + i];
				}
				ArraySource ss2(cipher, CipherSize, true,
					new PK_DecryptorFilter(rng, d,
						new ArraySink(recover, len)));
				for (int i = 0; i < receiveLen; ++i) {
					recoverFile << recover[i];
				}
			}
			break;
		}
		default: {
			break;
		}
	}
	cipherFile.close();
	recoverFile.close();
}

void MYRSA::Sign(char* signMsg, char* signOutPath) {


}

bool MYRSA::VerifySign(char* vsignPath) {

	return false;
}

// Encryption Scheme (OAEP using SHA)
void MYRSA::RSAEncOAEP(uint8_t* Data, size_t Size) {

	AutoSeededRandomPool rng;
	// Obtain Keys
	uint8_t* plain = (uint8_t*)malloc(Size);
	uint8_t* cipher = (uint8_t*)malloc(CipherSize);
	uint8_t* recover = (uint8_t*)malloc(Size);
	memcpy(plain, Data, Size);

	// Encryption
	//RSAES_OAEP_SHA_Encryptor e(pubKey);
	//RSAES_PKCS1v15_Encryptor e(pubKey);
	switch (padding) {
		case _PKCS1v15: {
			RSAES_PKCS1v15_Encryptor e(pubKey);
			ArraySource ss1(plain, Size, true,
				new PK_EncryptorFilter(rng, e,
					new ArraySink(cipher, CipherSize)));
			break;
		}
		case _OAEP: {
			RSAES_OAEP_SHA_Encryptor e(pubKey);
			ArraySource ss1(plain, Size, true,
				new PK_EncryptorFilter(rng, e,
					new ArraySink(cipher, CipherSize)));
			break;
		}
		default: {
			break;
		}
	}

	// Decryption
	//RSAES_OAEP_SHA_Decryptor d(privKey);
	//RSAES_PKCS1v15_Decryptor d(privKey);
	switch (padding) {
		case _PKCS1v15: {
			RSAES_PKCS1v15_Decryptor d(privKey);
			ArraySource ss2(cipher, CipherSize, true,
				new PK_DecryptorFilter(rng, d,
					new ArraySink(recover, Size)));
			break;
		}
		case _OAEP: {
			RSAES_OAEP_SHA_Decryptor d(privKey);
			ArraySource ss2(cipher, CipherSize, true,
				new PK_DecryptorFilter(rng, d,
					new ArraySink(recover, Size)));
			break;
		}
		default: {
			break;
		}
	}

	// Compare
	compare(plain, recover, Size);
	//InvertibleRSAFunction tmp;

#if DEBUG_PRINT
	std::cout << "    ===============================================\n";
	std::cout << "[*] DEBUG : RSAEncOAEP()" << endl;
	//showParam(tmp);
	std::cout << "    keySize  : " << keySize << endl;
	std::cout << "    CipherSize : " << CipherSize << endl;
	std::cout << "    Size     : " << Size << endl;
	std::cout << "[*] Plain  : " << endl;
	hexdump(plain, Size);
	std::cout << "[*] Cipher  : " << endl;
	hexdump(cipher, CipherSize);
	std::cout << "[*] Recover : " << endl;
	hexdump(recover, Size);
#endif // DEBUG_PRINT

	free(plain);
	free(cipher);
	free(recover);
}

// Signature Scheme (PKCS v1.5)
void MYRSA::RSASignPKCS(uint8_t* Data, size_t Size) {

	AutoSeededRandomPool rng;

	// Message
	uint8_t* message = (uint8_t*)malloc(Size);
	uint8_t* signature = (uint8_t*)malloc(CipherSize);
	uint8_t* msg_sig = (uint8_t*)malloc(Size + CipherSize);
	memcpy(message, Data, Size);

	// Sign and Encode
	RSASSA_PKCS1v15_SHA_Signer signer(privKey);
	ArraySource ss1(message, Size, true,
		new SignerFilter(rng, signer,
			new ArraySink(signature, CipherSize))
	);

	memcpy(msg_sig + 0, message, Size);
	memcpy(msg_sig + Size, signature, CipherSize);

	// Verify and Recover
	RSASSA_PKCS1v15_SHA_Verifier verifier(pubKey);
	ArraySource ss2(msg_sig, Size + CipherSize, true,
		new SignatureVerificationFilter(verifier, NULL,
			SignatureVerificationFilter::THROW_EXCEPTION)
	);

#if DEBUG
	std::cout << "    ===============================================\n";
	std::cout << "[*] DEBUG : RSASignPKCS()" << endl;
	std::cout << "    Size     : " << Size << endl;
	std::cout << "    keySize  : " << keySize << endl;
	std::cout << "    CipherSize : " << CipherSize << endl;
	std::cout << "[*] Message  : " << endl;
	hexdump(message, Size);
	std::cout << "[*] Sign     : " << endl;
	hexdump(signature, CipherSize);
	std::cout << "[*] Msg+Sign : " << endl;
	hexdump(msg_sig, Size + CipherSize);
#endif

	free(message);
	free(signature);
	free(msg_sig);
}

void MYRSA::Run(uint8_t* Data, size_t Size) {
	MYRSA RSAKey(&Size);

	RSAKey.RSAEncOAEP(Data, Size);
	RSAKey.RSASignPKCS(Data, Size);

}


void compare(uint8_t* a, uint8_t* b, size_t Size) {
	int x = 0;
	for (int i = 0; i < Size; i++)
		COMPARE(a[i], b[i], x);
	if (x) {
		std::cout << "[-] DIFF" << endl;
		exit(0);
	}
}

void hexdump(void* ptr, int buflen) {
	if (!buflen)
		return;
	unsigned char* buf = (unsigned char*)ptr;
	printf("%s\n", buf);
	printf("    ");
	for (int i = 1; i < buflen + 1; i++) {
		printf("%02x ", buf[i - 1]);
		if (!(i & 0xf))
			printf("\n    ");
	}
	if (buflen & 0xf)
		printf("\n");
	printf("\n");
}

void showParam(InvertibleRSAFunction params) {
	// Generated Parameters
	const Integer& n = params.GetModulus();
	const Integer& p = params.GetPrime1();
	const Integer& q = params.GetPrime2();
	const Integer& d = params.GetPrivateExponent();
	const Integer& e = params.GetPublicExponent();

	// Dump
	std::cout << "[*] RSA Parameters :" << endl;
	std::cout << "    n: " << n << endl;
	std::cout << "    p: " << p << endl;
	std::cout << "    q: " << q << endl;
	std::cout << "    d: " << d << endl;
	std::cout << "    e: " << e << endl;
}
