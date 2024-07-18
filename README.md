# AES Encryption Example

This is a Java implementation of AES (Advanced Encryption Standard) encryption and decryption using the GCM (Galois/Counter Mode) mode of operation.

## **Advanced Encryption Standard (AES)**

- It was publish by NIST in 2001.
- It is widely used.
- It is developed as an alternative to the DES algorithm.
- AES is a family of block ciphers that consists of ciphers of different key lengths and block sizes.
- AES works on the methods of substitution and permutation.

## **Working of AES**
1. First, the plaintext data is turned into blocks, and then the encryption is applied using the encryption key.
2. The encryption process consists of various sub-processes such as sub bytes, shift rows, mix columns, and add round keys. Depending upon the size of the key, 10, 12, or 14 such rounds are performed.
3. t’s worth noting that the last round doesn’t include the sub-process of mix columns among all other sub-processes performed to encrypt the data.

## **Advantage of Using the AES Encryption Algorithm**

AES is the most widely used encryption algorithm — it’s used in many applications, including:

- Wireless security,
- Processor security and file encryption,
- SSL/TLS protocol (website security),
- Wi-Fi security,
- Mobile app encryption,
- Most VPNs (virtual private network), etc.
