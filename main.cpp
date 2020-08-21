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

int main(int argc, char* argv[]) {

#if DEBUG_MAIN
    MYRSA key;

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
    
    char data[300] = "did_you_get_it";
    int n = 245;
    //for (int i = 0; i < n; i++) data[i] = i;

    MYRSA key(RSAPublicPath, RSAPrivatePath);
    //key.RSAEnc(data, n);
    key.RSASignPKCS(data, n);

    cout << "Hello World!\n" << endl;
#endif // DEUBG_PART
    
    return 0;
}