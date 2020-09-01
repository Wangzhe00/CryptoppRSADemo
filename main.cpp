#include "MYRSA.h"

using namespace std;
using namespace CryptoPP;

char pubPath[MAX_PATH_LEN];
char priPath[MAX_PATH_LEN];
char plainPath[MAX_PATH_LEN];
char cipherPath[MAX_PATH_LEN];
char recoverPath[MAX_PATH_LEN];
char signOutPath[MAX_PATH_LEN];
char vsignPath[MAX_PATH_LEN];
char signMsg[MAX_MSG_LEN];
PADDING padding = _PKCS1v15;

using namespace std;
using namespace CryptoPP;

// debug verify sign

RSA::PrivateKey _privKey;

uint8_t tmpData[1000];
char _signMsg[] = "YUN_SliceTools-3213-1599304743";
string pri =       "MIIEowIBAAKCAQEAzL28p22weHjGXbte9avs56fuWpy5cFc0LJK6UuCmTXLzyuv6\n\
                    TqJ3dd5mNb7VWAXPVL2B+V1Cwoaxa1HfrXIJwkbNU7ajpFRT6mRGO7PBHSagg97F\n\
                    Jpr5hogsPW2sk7dIce1qthMjnvKlvRQvF6YaeN98KYxpv187MAlswxogeZV+BtMv\n\
                    h/Ysg0oAujRU0we5+/1JSjqkuZ9UnZxVV5wmF3DaOW5t0jKlaMWcYayWaVzWQqxK\n\
                    CXhaycW2BPJ6FCX3x+M3/tIyOXtzaBB0QLqPvPpluiZl7Eg8ahGxsYfTg322XpV2\n\
                    lpAKbDubkf+MNPlPo1nqncjzFXBBPxpvv4Ic6wIDAQABAoIBAGmnA6I2lVklod+e\n\
                    oBsQdDj6zKIPvBW/ulnCAcpgyRCwYCP37/wCFLlLYd0cNAWvQdVN0bN3r8qoLQff\n\
                    gRiE/4o0dSJc3kcfiQosYp3OXboIQ86o9327fUYyIPo2DVdQvl6kEGwSplAQkPxo\n\
                    XQDMI176nJzoK22o2+cnBewMIHP8hibmlLathOxoQKV/nlPU5S6yVmX0r0pEuxoW\n\
                    ceMKyETECpbURZmcsXXNyM24yxSRJsm+dCKYJv48bbECw5MCheaJZR7ERHWBOClD\n\
                    5yG1TzOVH6uhfSVX/n/z4eK11MMBXX1m1v8XPv30vfHlG+DtePX/r96aCyF8nB7A\n\
                    LebSmmkCgYEA/och1M/KFXD+lG7p0tmTERwJ+Gpj3l4sKN2Zvc2PIEZI3bkJu3ll\n\
                    nki3OvzwlyRc3RqD4T27uDN8xvNSvqC2KARG2GSq0sWSjcqZJaVAmS7RzhqYv/wu\n\
                    zcy4YzKOe57WSDaaTPVISHjs5zYYXFJEcFbrHzhA4XaV4wZ+Zh6fhK8CgYEAzezj\n\
                    S28pHkVUCXVS2dFIFN/7/2Y9D/z28QxehMkQSl05R8p02OCo6YYd4OyTatzWxMZ4\n\
                    CypuhsIDDQTT5ALaC6mqzcz/IW2k++lrhozosYkXixrVF8HevNz2OGkhRR0tE8xe\n\
                    t2dTJE9ICz8yxbZp23b4Oy0jSamiXN0JVtrIMoUCgYEAr5hQib3Un9g1effOzo0V\n\
                    /d7HLh9PyNBVTNgcwan3zP9QM879XN4SchGef06TOOJ4Qn2RcCojwJ+cvLCPbD35\n\
                    jT/uFEnW49Q0GCgmYadRGp0HV1ZX/VMggxByQNVXIQfisy0gZGlvtbffUF+sjLyg\n\
                    xJPiX8ZyVFl4bIhFWXRU/rcCgYAz2fApsGXUH3TXpNkly5Kw3u1fE+lQO0wayhiK\n\
                    qu4VK4Ae2ZWufnNJyeGAH1HHWLAjgC398cM+319RSePox+cLhL9jbrjXO/qNC+tt\n\
                    R9HX0kNBXZJGlyR0vdapwZ8E/iG5mH5JBBVlUSk82773FcV143EBxY3bIIGnjGir\n\
                    nA9I2QKBgDbYuzrsZ2cHNwqwDxVKrma5bLKIK4KIRKUgDv5zvCb4xWybwKe2kpVf\n\
                    ozJTey/S8EbZpHfLzQS5Z9af6Aav0NzqckL4O9FvpUJ4N4I8JgN5C/5bVoVRYeBz\n\
                    CryZBdXo29bBs6LCU9QfSqqfWv7N1mGVFWPYgKIdyuDM8cOCTjMu";
void testBase() {
    // "CBC Mode Test", without '\0'
    ByteQueue priQueue;
    Base64Decoder priDecoder;

    priDecoder.Attach(new Redirector(priQueue));
    priDecoder.Put((const byte*)pri.data(), pri.length());
    priDecoder.MessageEnd();


    // Use different functions depending on the  private key type
    bool PKCS8 = false;
    try {
        //puts("your private key is PKCS#1");
        _privKey.BERDecodePrivateKey(priQueue, false, priQueue.MaxRetrievable());
        PKCS8 = true;
    }
    catch (Exception e) {}
    if (!PKCS8) {
        _privKey.BERDecode(priQueue);
    }

    InvertibleRSAFunction priParams;
    priParams.Initialize(_privKey.GetModulus(), _privKey.GetPublicExponent(), _privKey.GetPrivateExponent());

    int keySize = _privKey.GetModulus().BitCount();
    int _CipherSize = keySize > 2000 ? 256 : 128;

    cout << "pri N: " << _privKey.GetModulus() << endl;
    cout << "pri E: " << _privKey.GetPublicExponent() << endl;
    cout << "pri D: " << _privKey.GetPrivateExponent() << endl;

    // Create Keys
    RSA::PrivateKey _(priParams);
    _privKey = _;
    AutoSeededRandomPool rng;

    int msgLen = (int)strlen(_signMsg);
    uint8_t* message = (uint8_t*)malloc(msgLen);
    memcpy(message, _signMsg, msgLen);
    uint8_t* signature = (uint8_t*)malloc(_CipherSize);
    uint8_t* msgSign = (uint8_t*)malloc(msgLen + _CipherSize);

    RSASSA_PKCS1v15_SHA_Signer signer(_privKey);
    ArraySource ss1(message, msgLen, true,
        new SignerFilter(rng, signer,
            new ArraySink(signature, _CipherSize))
    );

    //printf("This is debug: %s\n", signature);

    unsigned char plainText[] = { 67, 66, 67, 32, 77, 111, 100, 101, 32, 84, 101, 115, 116 };
    string encoded;
    if (true) {
        Base64Encoder encoder;
        encoder.Put(plainText, sizeof(plainText));
        encoder.MessageEnd();

        word64 size = encoder.MaxRetrievable();
        if (size) {
            encoded.resize(size);
            encoder.Get((byte*)&encoded[0], encoded.size());
        }
        cout << encoded << endl;
    }
    encoded = "ZadpuslEUd4lRKDJQ+s0Nxqr1LkKEVojqhtFS0stcJMD3Z7aKpSY3ZSBnAjwKyAhkMSpkZefGojxNRj1XYuAbJ8HLfc1sdS6w6CobHah06FdrAL0zpdUOhCNYzsgLui0jagxYiVyMEUr+67/NCuINm71UEAy0zyHnQwWFOgzsQ0tdYhzET9zWXjnS7vf1sO3sOlg3LhgaKp3GnnzthNfgTZQpL9CI+SgdrKepzsZsYq291xyiNVqrBnZ1+7UL1b0GSniKQGuFd5LSY2zpjBzvubobAUSiKfZ5gPJ/OeqUa44D7kPeBQTlFFduIgDJ06fuhX2GbNEhb/WEWKZNz4ncA==";
    string decoded;
    Base64Decoder decoder;
    decoder.Put((byte*)encoded.data(), encoded.size());
    decoder.MessageEnd();

    word64 size = decoder.MaxRetrievable();
    if (size && size <= SIZE_MAX) {
        decoded.resize(size);
        decoder.Get((byte*)&decoded[0], decoded.size());
    }
    cout << decoded << endl;
}

uint8_t ret[1000];

int main(int argc, char* argv[]) {

#if DEBUG_MAIN
    MYRSA key;
    /*string _ = "ZadpuslEUd4lRKDJQ+s0Nxqr1LkKEVojqhtFS0stcJMD3Z7aKpSY3ZSBnAjwKyAhkMSpkZefGojxNRj1XYuAbJ8HLfc1sdS6w6CobHah06FdrAL0zpdUOhCNYzsgLui0jagxYiVyMEUr+67/NCuINm71UEAy0zyHnQwWFOgzsQ0tdYhzET9zWXjnS7vf1sO3sOlg3LhgaKp3GnnzthNfgTZQpL9CI+SgdrKepzsZsYq291xyiNVqrBnZ1+7UL1b0GSniKQGuFd5LSY2zpjBzvubobAUSiKfZ5gPJ/OeqUa44D7kPeBQTlFFduIgDJ06fuhX2GbNEhb/WEWKZNz4ncA==";
    
    key.Base642Uint8_t(_, ret);
    cout << key.Uint8_t2Base64(ret) << endl;

    return 0;*/

    if (strcmp(argv[1], "-h") == 0) {
        printf("1> Encrypt a file: main.exe -pub pub -enc plain.txt -out cipher.txt [-p]\n");
        printf("2> Decrypt a file: main.exe -pri pri -dec cipher.txt -out recover.txt [-p]\n");
        printf("3> Sign:           main.exe -pri pri -sign ok -out signed.txt\n");
        printf("4> Verify Sign:    main.exe -pub pub -vsign signed.txt\n");
        printf("5> Help            main.exe -h\n");
        return 0;
    }

    if (strcmp(argv[3], "-enc") == 0) {
        _ASSERT(argc == 7 || argc == 8);
        _ASSERT(strcmp(argv[1], "-pub") == 0);
        _ASSERT(strcmp(argv[5], "-out") == 0);
        if (argc > 7 && strcmp(argv[7], "-p") == 0) {
            padding = _OAEP;
        }
        memcpy(pubPath, argv[2], strlen(argv[2]));
        memcpy(plainPath, argv[4], strlen(argv[4]));
        memcpy(cipherPath, argv[6], strlen(argv[6]));
        key.SetPublibKey(pubPath);
        key.Encryption(plainPath, cipherPath);
    } else if (strcmp(argv[3], "-dec") == 0) {
        _ASSERT(argc == 7 || argc == 8);
        _ASSERT(strcmp(argv[1], "-pri") == 0);
        _ASSERT(strcmp(argv[5], "-out") == 0);
        if (argc > 7 && strcmp(argv[7], "-p") == 0) {
            padding = _OAEP;
        }

        memcpy(priPath, argv[2], strlen(argv[2]));
        memcpy(cipherPath, argv[4], strlen(argv[4]));
        memcpy(recoverPath, argv[6], strlen(argv[6]));
        key.SetPrivateKey(priPath);
        key.Decryption(cipherPath, recoverPath);
    } else if (strcmp(argv[3], "-sign") == 0) {
        _ASSERT(argc == 7);
        _ASSERT(strcmp(argv[1], "-pri") == 0);
        _ASSERT(strcmp(argv[5], "-out") == 0);

        memcpy(priPath, argv[2], strlen(argv[2]));
        memcpy(signMsg, argv[4], strlen(argv[4]));
        memcpy(signOutPath, argv[6], strlen(argv[6]));
        key.SetPrivateKey(priPath);
        key.Sign(signMsg, signOutPath);
    } else if (strcmp(argv[3], "-vsign") == 0) { 
        _ASSERT(argc == 5);
        _ASSERT(strcmp(argv[1], "-pub") == 0);
        memcpy(pubPath, argv[2], strlen(argv[2]));
        memcpy(vsignPath, argv[4], strlen(argv[4]));
        key.SetPublibKey(pubPath);
        printf("%s\n", key.VerifySign(vsignPath) ? "Succeed" : "Failed");
    } else {
        cout << argc << endl;
        for (int i = 0; i < argc; i++) {
            printf("%s\n", argv[i]);
        }
    }
#endif // DEBUG_MAIN

#if DEUBG_PART

    //testBase();
    string RSAPublicKey = "\
		MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4OjHX+sp9NaFHlUSsNLC\n\
		aaxKY+AnZrq0cUH1dIH9sQLUbOnxNxFcFW7rthXFvFwCPPGcWrYd7XNfYaH/7oF8\n\
		UXPOdcgg0SrhBAg80Xb+TAoxJWDiuy3yWY5lO5gMfp8z7sEG48krt6qFqHtO6Al1\n\
		0iLtXk5K+kT82grPQELySMPv4J8s+ovCgclwDvMcD2EUZjFr5Vfuo76qpa1AsUgG\n\
		O6B0opWTID+d1JBQO17CpTiQQRMS9mRF1gRZoLR+TLx76hUhdWFPdDVC/1tv53wT\n\
		rSehshvgTogQe9PFFRpWyK2gc8LjS0LXcuqvlDHiB8d4nv6KAff3CHE9W2aUajMh\n\
		oQIDAQAB";
    ByteQueue pubQueue;
    Base64Decoder pubDecoder;
    RSAFunction pubParams;

    RSA::PublicKey _pubKey;

    pubDecoder.Attach(new Redirector(pubQueue));
    pubDecoder.Put((const byte*)RSAPublicKey.data(), RSAPublicKey.length());
    pubDecoder.MessageEnd();
    _pubKey.BERDecode(pubQueue);
    pubParams.Initialize(_pubKey.GetModulus(), _pubKey.GetPublicExponent());

    int _keySize = _pubKey.GetModulus().BitCount();
    int _CipherSize = _keySize > 2000 ? 256 : 128;


    string tmp, tmp1;
    // cipher
    char a[] = "ZadpuslEUd4lRKDJQ+s0Nxqr1LkKEVojqhtFS0stcJMD3Z7aKpSY3ZSBnAjwKyAhkMSpkZefGojxNRj1XYuAbJ8HLfc1sdS6w6CobHah06FdrAL0zpdUOhCNYzsgLui0jagxYiVyMEUr+67/NCuINm71UEAy0zyHnQwWFOgzsQ0tdYhzET9zWXjnS7vf1sO3sOlg3LhgaKp3GnnzthNfgTZQpL9CI+SgdrKepzsZsYq291xyiNVqrBnZ1+7UL1b0GSniKQGuFd5LSY2zpjBzvubobAUSiKfZ5gPJ/OeqUa44D7kPeBQTlFFduIgDJ06fuhX2GbNEhb/WEWKZNz4ncA==";
    string date;

    // base64 decoder

    StringSource(a, true, new Base64Decoder(new StringSink(date)));
    
    
    //StringSource(a, true, new Base64Decoder(new StringSink(tmpData)));
    cout << date << endl;
    printf("%s\n", date.c_str());
    hexdump(date, date.size());
    string date1 = "YUN_SliceTools-3213-1599304743" + date;


    byte* msgSign = (byte*)malloc(date1.size());
    int len = date1.size();
    for (int i = 0; i < len; i++) {
        msgSign[i] = (byte) date1[i];
    }

    // Verify and Recover
    RSASSA_PKCS1v15_SHA_Verifier verifier(_pubKey);

    try {
        ArraySource ss2(msgSign, len, true,
            new SignatureVerificationFilter(verifier, NULL,
                SignatureVerificationFilter::THROW_EXCEPTION));

        //ArraySource ss2(date1, true,
        //    new SignatureVerificationFilter(verifier, NULL,
        //        SignatureVerificationFilter::THROW_EXCEPTION));
        puts("Yes");
    } catch (const exception ex) {
        //cerr << ex.what() << endl;
        puts("No");
    }
    std::free(msgSign);



    /*
    char data[300] = "did_you_get_it";
    int n = 245;
    //for (int i = 0; i < n; i++) data[i] = i;

    MYRSA key(RSAPublicPath, RSAPrivatePath);
    //key.RSAEnc(data, n);
    key.RSASignPKCS(data, n);

    cout << "Hello World!\n" << endl;*/
#endif // DEUBG_PART
    
    return 0;
}