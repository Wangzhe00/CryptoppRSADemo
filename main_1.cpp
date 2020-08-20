
/*
    Summarized as follows:
        (1) Encrypted padding
            \Brief: The meaning of padding is to ensure that the encrypted ciphertext is different each time,even if the plaintext is the same.
            1> OAEP<SHA1>
                1) Brief: The full name of OAEP is Optimal Asymmetric Encryption Padding.42 bytes in total.
                2) Encrypted bytes: 1024 bit -> 86 bytes, 2048 bit -> 214 bytes.
                3) Advantage: safer than PKCS1v15
                4) Disadvantage: less content encrypted at one time than PKCS1v15
            2> PKCS1v15
                1) Brief: The most commonly used mode.11 bytes in total.
                2) Encrypted bytes: 1024 bit -> 117 bytes, 2048 bit -> 245 bytes.
                3) Advantage:  more content encrypted at one time than OAEP
                4) Disadvantage: less secure than OAEP

        (2) OAEP padding calculation method.[1024 length as an example]
            1) The length of data that can be encrypted using RSA is determined primarily by the size of the key you're using. You appear to be using OAEP, so the maximum length is:
                plainLength = keyLength - 2 - 2 * hashLength

            2) Where keyLength is the length of the RSA modulus in bytes. You're using a 1024 bit key so:
                keyLength = 1024 / 8 = 128

            3) And since you're using OAEP with SHA-1
                hashLength = 20

            4) So the maximum you can encrypt is:
                keyLength = 128 - 2 - 2 * 20 = 86

            2048 bits is similar to the above.

            [*]Expansion: The padding length of PKCS#1 is 11 Bytes.
    */


#include <iostream> 
#include <fstream>
#include "RSAKeyPair.h"


using namespace std;
using namespace CryptoPP;



char RSAPublicPath[] = "public_key.txt";
char RSAPrivatePath[] = "private_key.txt";

string RSAPublicKey;
string RSAPrivateKey;

char pubPath[100];
char priPath[100];
char plainPath[100];
char cipherPath[100];
char recoverPath[100];
char signOutPath[100];
char signMsg[100];
char vsignPath[100];
PADDING padding = _PKCS1v15;

/*
PKCS#8密钥格式，多用于JAVA、PHP程序加解密中，为目前用的比较多的密钥、证书格式；
PKCS#1密钥格式，多用于JS等其它程序加解密，属于比较老的格式标准。
PKCS#1和PKCS#8的主要区别，从本质上说，PKCS#8格式增加验证数据段，保证密钥正确性。
*/


void initRSAKey() {
    ifstream RSAPublicFile, RSAPrivateFile;
    RSAPublicFile.open(RSAPublicPath, ios::in);
    RSAPrivateFile.open(RSAPrivatePath, ios::in);

    if (!RSAPublicFile || !RSAPrivateFile) {
        /* check your file name */
        cout << "failed open... maybe the file name is wrong..\n";
    }
    string tmp[MAXLINE], tmp1[MAXLINE];
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
    

    ofstream outFile2("outPrivateKey.txt", ios::out);
    ofstream outFile1("outPublicKey.txt", ios::out);
    outFile1 << RSAPublicKey;
    outFile2 << RSAPrivateKey;
    outFile1.close();
    outFile2.close();
}

void catPublicParameters() {

    // cat N,E,D of publicKey
    ByteQueue queue;
    Base64Decoder decoder;
    decoder.Attach(new Redirector(queue));
    decoder.Put((const byte*)RSAPublicKey.data(), RSAPublicKey.length());
    decoder.MessageEnd();

    /* backup the secret key, no practical use. */
    FileSink fs("decoded-key.der");
    queue.CopyTo(fs);
    fs.MessageEnd();

    try {
        RSA::PublicKey rsaPublic;
        //rsaPublic.BERDecodePublicKey(queue, false, queue.MaxRetrievable());
        rsaPublic.BERDecode(queue);

        AutoSeededRandomPool prng;
        bool valid = rsaPublic.Validate(prng, 3);
        if (!valid) {
            cerr << "RSA public key is not valid" << endl;
        }
        cout << "N: " << rsaPublic.GetModulus() << endl;
        cout << "E: " << rsaPublic.GetPublicExponent() << endl;
    } catch (const exception& ex) {
        cerr << ex.what() << endl;
        //exit(1);
    }
}

void catPrivateParameters() {

    // cat N,E,D of privateKey
    ByteQueue queue;
    Base64Decoder decoder;
    decoder.Attach(new Redirector(queue));
    decoder.Put((const byte*)RSAPrivateKey.data(), RSAPrivateKey.length());
    decoder.MessageEnd();

    /* backup the secret key, no practical use. */
    FileSink fs("decoded-key.der");
    queue.CopyTo(fs);
    fs.MessageEnd();

    try {
        RSA::PrivateKey rsaPrivate;
        /*
            PKCS#8密钥格式，多用于JAVA、PHP程序加解密中，为目前用的比较多的密钥、证书格式；
            PKCS#1密钥格式，多用于JS等其它程序加解密，属于比较老的格式标准。
            PKCS#1和PKCS#8的主要区别，从本质上说，PKCS#8格式增加验证数据段，保证密钥正确性。
        */
        // rsaPrivate.BERDecodePrivateKey(queue, false, queue.MaxRetrievable()); // PKCS#1
        // rsaPrivate.BERDecode(queue); // PKCS#8
        try {
            rsaPrivate.BERDecodePrivateKey(queue, false, queue.MaxRetrievable());
        }
        catch (const exception& ex) {
            puts("your private key is PKCS#8");
            rsaPrivate.BERDecode(queue);
        }

        AutoSeededRandomPool prng;
        bool valid = rsaPrivate.Validate(prng, 3);
        if (!valid) {
            cerr << "RSA private key is not valid" << endl;
        }
        cout << "N: " << rsaPrivate.GetModulus() << endl;
        cout << "E: " << rsaPrivate.GetPublicExponent() << endl;
        cout << "D: " << rsaPrivate.GetPrivateExponent() << endl;

    }
    catch (const exception& ex) {
        cerr << ex.what() << endl;
        //exit(1);
    }
}


int main(int argc, char* argv[]) {

#if  DEBUG_FILES
    initRSAKey();
    catPublicParameters();  // (n,e)
    catPrivateParameters(); // (n,d)
#endif //  DEBUG_FILES

#if DEBUG_MAIN

    printf("argc = %d\n", argc);
    MYRSA key;

    if (strcmp(argv[1], "-h") == 0) {
        printf("1> Encrypt a file: main.exe -pub pub -enc hello.txt -out encrypted.txt\n");
        printf("2 > Decrypt a file : main.exe - pri pri - dec hello.txt - out primary.txt\n");
        printf("3 > Sign:           main.exe - pri pri - sign ok - out signed.txt\n");
        printf("4 > Verify Sign : main.exe - pub pub - vsign vsign.txt\n");
        printf("5 > Help            main.exe - h\n");
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
    }
    else if (strcmp(argv[3], "-dec") == 0) {
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
    }
    else if (strcmp(argv[3], "-sign") == 0) {
        _ASSERT(argc == 7);
        _ASSERT(strcmp(argv[1], "-pri") == 0);
        _ASSERT(strcmp(argv[5], "-out") == 0);

        memcpy(priPath, argv[2], strlen(argv[2]));
        memcpy(signMsg, argv[4], strlen(argv[4]));
        memcpy(signOutPath, argv[6], strlen(argv[6]));
        key.SetPrivateKey(pubPath);
        key.Sign(plainPath, cipherPath);
    }
    else if (strcmp(argv[3], "-vsign") == 0) {
        _ASSERT(argc == 5);
        _ASSERT(strcmp(argv[1], "-pub") == 0);
        memcpy(priPath, argv[2], strlen(argv[2]));
        memcpy(vsignPath, argv[4], strlen(argv[4]));
        key.SetPublibKey(pubPath);
        printf("%s\n", key.VerifySign(vsignPath) ? "Succeed" : "Failed");
    }
#endif // DEBUG_MAIN

#if DEUBG_PART
    
    uint8_t data[300];
    int n = 245;
    for (int i = 0; i < n; i++) data[i] = i;

    MYRSA key(RSAPublicPath, RSAPrivatePath);
    key.RSAEncOAEP(data, n);
    key.RSASignPKCS(data, n);

#endif // DEUBG_PART

    cout << "Hello World!\n" << endl;
    return 0;
}