#include "MYRSA.h"

using namespace std;
using namespace CryptoPP;

#define MAXLINE 100
#define COMPARE(a, b, x) x += (a - b)

extern PADDING padding;

MYRSA::MYRSA() {
	keySize = 0;
	CipherSize = 0;
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
	
	keySize = pubKey.GetModulus().BitCount();
	CipherSize = keySize > 2000 ? 256 : 128;

#if DEBUG_PRINT
	cout << "pub N: " << pubKey.GetModulus() << endl;
	cout << "pub E: " << pubKey.GetPublicExponent() << endl << endl;
	cout << "pri N: " << privKey.GetModulus() << endl;
	cout << "pri E: " << privKey.GetPublicExponent() << endl;
	cout << "pri D: " << privKey.GetPrivateExponent() << endl;
#endif // DEUBG_PRINT

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
	RSAFunction pubParams;

	pubDecoder.Attach(new Redirector(pubQueue));
	pubDecoder.Put((const byte*)RSAPublicKey.data(), RSAPublicKey.length());
	pubDecoder.MessageEnd();
	pubKey.BERDecode(pubQueue);
	pubParams.Initialize(pubKey.GetModulus(), pubKey.GetPublicExponent());

	keySize = pubKey.GetModulus().BitCount();
	CipherSize = keySize > 2000 ? 256 : 128;

#if DEBUG_PRINT
	cout << "pub N: " << pubKey.GetModulus() << endl;
	cout << "pub E: " << pubKey.GetPublicExponent() << endl << endl;
#endif // DEBUG_PRINT

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

	keySize = privKey.GetModulus().BitCount();
	CipherSize = keySize > 2000 ? 256 : 128;

#if DEBUG_PRINT
	cout << "pri N: " << privKey.GetModulus() << endl;
	cout << "pri E: " << privKey.GetPublicExponent() << endl;
	cout << "pri D: " << privKey.GetPrivateExponent() << endl;
#endif // DEBUG_PRINT

	// Create Keys
	RSA::PrivateKey privateKey(priParams);
	privKey = privateKey;
}

void MYRSA::Encryption(char* plainPath, char* cipherPath) {
	ifstream plainFile;
	ofstream cipherFile;
	plainFile.open(plainPath, ios::in);
	cipherFile.open(cipherPath, ios::out);

	string tmp, data;
	int len = 0;
	while (getline(plainFile, tmp)) {
		len += (int)tmp.size();
		data += tmp;
	}

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
					cipherFile << Uint8_t2HexString(cipher[i]);
				}
				std::free(plain);
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
#endif // DEBUG_PRINT

			}
			std::free(cipher);
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
					cipherFile << Uint8_t2HexString(cipher[i]);
				}
				std::free(plain);
			}
			std::free(cipher);
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

	string tmp, tmp1;

	while (getline(cipherFile, tmp)) {
		tmp1 += tmp;
	}
	// cipher
	uint8_t* data = (uint8_t*)malloc(tmp1.size() / 2);
	for (int i = 0; i < tmp1.size(); i += 2) {
		data[i >> 1] = HexString2Uint8_t(tmp1[i], tmp1[i + 1]);
	}
	int len = (int)(tmp1.size()) >> 1;


#if DEBUG_PRINT
	std::cout << "    ===============================================\n";
	std::cout << "    keySize  : " << keySize << endl;
	std::cout << "    CipherSize : " << CipherSize << endl;
	std::cout << "    Size     : " << len << endl;
	std::cout << "[*] Cipher  : " << endl;
	hexdump(data, len);
#endif // DEBUG_PRINT

	switch (padding) {
		case _PKCS1v15: {
			// The length must be a multiple of CipherSize, because RSA is encrypted in blocks
			_ASSERT(len % CipherSize == 0);

			RSAES_PKCS1v15_Decryptor d(privKey);

			int roundNum = len / CipherSize;
			int receiveLen = keySize / 8 - 11;

			uint8_t* cipher = (uint8_t*)malloc(CipherSize);
			uint8_t* recover = (uint8_t*)malloc(receiveLen);

			for (int st = 0; st < roundNum; ++st) {
				memset(recover, 0, receiveLen);
				// Update the cipher every round.
				for (int i = 0; i < CipherSize; ++i) {
					cipher[i] = data[st * CipherSize + i];
				}
				ArraySource ss2(cipher, CipherSize, true,
					new PK_DecryptorFilter(rng, d,
						new ArraySink(recover, receiveLen)));
				// Write the obtained plaintext into the recoverPath, the last block size may be smaller than {receiveLen}, be careful not to print extra characters.
				for (int i = 0; i < receiveLen; ++i) {
					if (recover[i] == 0) break;
					recoverFile << recover[i];
				}
			}
			std::free(cipher);
			std::free(recover);
			break;
		}
		case _OAEP: {
			// The length must be a multiple of CipherSize, because RSA is encrypted in blocks
			_ASSERT(len % CipherSize == 0);

			RSAES_OAEP_SHA_Decryptor d(privKey);

			int roundNum = len / CipherSize;
			int receiveLen = keySize / 8 - 42;

			uint8_t* cipher = (uint8_t*)malloc(CipherSize);
			uint8_t* recover = (uint8_t*)malloc(receiveLen);

			for (int st = 0; st < roundNum; ++st) {
				memset(recover, 0, receiveLen);
				// Update the cipher every round.
				for (int i = 0; i < CipherSize; ++i) {
					cipher[i] = data[st * CipherSize + i];
				}
				ArraySource ss2(cipher, CipherSize, true,
					new PK_DecryptorFilter(rng, d,
						new ArraySink(recover, receiveLen)));
				// Write the obtained plaintext into the recoverPath, the last block size may be smaller than {receiveLen}, be careful not to print extra characters.
				for (int i = 0; i < receiveLen; ++i) {
					if (recover[i] == 0) break;
					recoverFile << recover[i];
				}
			}
			std::free(cipher);
			std::free(recover);
			break;
		}
		default: { // Useless
			break;
		}
	}
	cipherFile.close();
	recoverFile.close();
	std::free(data);

}

void MYRSA::Sign(char* signMsg, char* signOutPath) {
	ofstream signOutFile(signOutPath, ios::out);
	
	int msgLen = (int)strlen(signMsg);
	_ASSERT(msgLen < 100);
	uint8_t* message = (uint8_t*)malloc(msgLen);
	memcpy(message, signMsg, msgLen);
	
	uint8_t* signature = (uint8_t*)malloc(CipherSize);
	uint8_t* msgSign = (uint8_t*)malloc(msgLen + CipherSize);

	//MD5 md5();
	//RSASSA_PKCS1v15_MD5_Signer signer(privKey, md5);
	RSASSA_PKCS1v15_SHA_Signer signer(privKey);
	ArraySource ss1(message, msgLen, true,
		new SignerFilter(rng, signer,
			new ArraySink(signature, CipherSize))
	);

	memcpy(msgSign + 0, message, msgLen);
	memcpy(msgSign + msgLen, signature, CipherSize);

	for (int i = 0; i < msgLen + CipherSize; i++) {
		signOutFile << Uint8_t2HexString(msgSign[i]);
	}

#if DEBUG_PRINT
	std::cout << "    ===============================================\n";
	std::cout << "[*] DEBUG : RSASignPKCS()" << endl;
	std::cout << "    Size     : " << msgLen << endl;
	std::cout << "    keySize  : " << keySize << endl;
	std::cout << "    CipherSize : " << CipherSize << endl;
	std::cout << "[*] Message  : " << endl;
	hexdump(message, msgLen);
	std::cout << "[*] Sign     : " << endl;
	hexdump(signature, CipherSize);
	std::cout << "[*] Msg+Sign : " << endl;
	hexdump(msgSign, msgLen + CipherSize);
#endif // DEBUG_PRINT

	std::free(message);
	std::free(signature);
	std::free(msgSign);
}

bool MYRSA::VerifySign(char* vsignPath) {
	ifstream vsignFile(vsignPath, ios::in);
	string tmp, tmp1;

	while (getline(vsignFile, tmp)) {
		tmp1 += tmp;
	}

	// cipher
	uint8_t* msgSign = (uint8_t*)malloc(tmp1.size() / 2);
	for (int i = 0; i < tmp1.size(); i += 2) {
		msgSign[i >> 1] = HexString2Uint8_t(tmp1[i], tmp1[i + 1]);
	}
	int len = (int)(tmp1.size()) >> 1;

	// Verify and Recover
	RSASSA_PKCS1v15_SHA_Verifier verifier(pubKey);

	//RSASSA_PKCS1v15_MD5_Verifier verifier(pubKey, md5);
	try {
		ArraySource ss2(msgSign, len, true,
			new SignatureVerificationFilter(verifier, NULL,
				SignatureVerificationFilter::THROW_EXCEPTION));
		std::free(msgSign);
		return true;
	}
	catch (const exception ex) {
		//cerr << ex.what() << endl;
		std::free(msgSign);
		return false;
	}
	
#if DEBUG_PRINT
	std::cout << "    ===============================================\n";
	std::cout << "[*] DEBUG : RSASignPKCS()" << endl;
	std::cout << "    Len     : " << len << endl;
	std::cout << "    keySize  : " << keySize << endl;
	std::cout << "    CipherSize : " << CipherSize << endl;
	std::cout << "[*] Msg+Sign : " << endl;
	hexdump(msgSign, len);
#endif // DEBUG_PRINT

}

// Encryption Scheme (OAEP using SHA)
void MYRSA::RSAEnc(uint8_t* Data, size_t Size) {
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
	std::cout << "[*] DEBUG :" << endl;
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

	std::free(plain);
	std::free(cipher);
	std::free(recover);
}

// Signature Scheme (PKCS v1.5)
void MYRSA::RSASignPKCS(char* Data, size_t Size) {

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

#if DEBUG_PRINT
	std::cout << "    ===============================================\n";
	std::cout << "[*] DEBUG : " << endl;
	std::cout << "    Size     : " << Size << endl;
	std::cout << "    keySize  : " << keySize << endl;
	std::cout << "    CipherSize : " << CipherSize << endl;
	std::cout << "[*] Message  : " << endl;
	hexdump(message, Size);
	std::cout << "[*] Sign     : " << endl;
	hexdump(signature, CipherSize);
	std::cout << "[*] Msg+Sign : " << endl;
	hexdump(msg_sig, Size + CipherSize);
#endif // DEBUG_PRINT

	std::free(message);
	std::free(signature);
	std::free(msg_sig);
}

string Uint8_t2HexString(uint8_t in) {
	string res = "";
	uint16_t _in = (uint16_t)in;
	res += (_in / 16 > 9) ? ('A' + _in / 16 - 10) : ('0' + _in / 16);
	res += (_in % 16 > 9) ? ('A' + _in % 16 - 10) : ('0' + _in % 16);
	return res;
}

uint8_t HexString2Uint8_t(char c1, char c2) {
	uint16_t res = 0;
	res += isalpha(c1) ? 16 * (10 + c1 - 'A') : 16 * (c1 - '0');
	res += isalpha(c2) ? (10 + c2 - 'A') : (c2 - '0');
	return (uint8_t)res;
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
