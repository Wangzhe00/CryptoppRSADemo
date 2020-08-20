# CryptoppRSADemo



The command line parameters and corresponding explanations are as follows:

```shell
-pub    # Public  key path
-pri    # Private key path
  	
-enc    # File to be encrypted
-out    # Encrypted file
-p      # Optional parameter, default padding is PKCS, plus -p means to change to OAEP padding

-dec    # File to be decrypted
-out    # Primary file
-p      # Optional parameter, default padding is PKCS, plus -p means to change to OAEP padding

-sign   # Msg
-out    # Signed file

-vsign  # Msg + sign file, result return to terminal

-t pub
```

Sample commands are as follows:

  ```shell
# Help            
main.exe -h

# Encrypt a file: padding using PKCS1v15
main.exe -pub pub -enc plain.txt -out cipher.txt

# Encrypt a file: padding using OAEP<SHA1>
main.exe -pub pub -enc plain.txt -out cipher.txt -p

# Decrypt a file: padding using PKCS1v15
main.exe -pri pri -dec cipher.txt -out recover.txt

# Decrypt a file: padding using OAEP<SHA1>
main.exe -pri pri -dec cipher.txt -out recover.txt -p

# Sign:           
main.exe -pri pri -sign ok -out signed.txt

# Verify Sign:    
main.exe -pub pub -vsign vsign.txt 
  ```



## Appendix

### Summarized as follows:

####  (1) Encrypted padding

- Brief: The meaning of padding is to ensure that the encrypted ciphertext is different each time,even if the plaintext is the same.
- **OAEP\<SHA1\>**

  -  **Brief**: The full name of OAEP is Optimal Asymmetric Encryption Padding.42 bytes in total.
  -  **Encrypted bytes**: 1024 bit -> 86 bytes, 2048 bit -> 214 bytes.
  -  **Advantage**: safer than PKCS1v15
  -  **Disadvantage**: less content encrypted at one time than PKCS1v15
- **PKCS1v15**

  -  **Brief**: The most commonly used mode.11 bytes in total.
     
  -  **Encrypted bytes**: 1024 bit -> 117 bytes, 2048 bit -> 245 bytes.
     
  -  **Advantage**:  more content encrypted at one time than OAEP
     
  -  **Disadvantage**: less secure than OAEP
                 
####  (2) OAEP padding calculation method.[1024 length as an example]

- 1) The length of data that can be encrypted using RSA is determined primarily by the size of the key you're using. You appear to be using OAEP, so the maximum length is:

  ```mathematica
  plainLength = keyLength - 2 - 2 * hashLength
  ```

- 2) Where keyLength is the length of the RSA modulus in bytes. You're using a 1024 bit key so:

  ```mathematica
  keyLength = 1024 / 8 = 128
  ```

- 3) And since you're using OAEP with SHA-1

  ```mathematica
  hashLength = 20
  ```

- 4) So the maximum you can encrypt is:

  ```mathematica
  keyLength = 128 - 2 - 2 * 20 = 86
  ```

​    **2048 bits is similar to the above.**

   **[*]Expansion**: The padding length of PKCS#1 is 11 Bytes.








​    