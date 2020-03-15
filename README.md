#### Golang CTF加解密工具

``` bash
----------------------------------------------------------
 ____          _               _  __           _ _
| __ ) _   _  | |   _   _  ___(_)/ _| ___ _ __/ / |
|  _ \| | | | | |  | | | |/ __| | |_ / _ \ '__| | |
| |_) | |_| | | |__| |_| | (__| |  _|  __/ |  | | |
|____/ \__, | |_____\__,_|\___|_|_|  \___|_|  |_|_|
       |___/
----------------------------------------------------------
QQ 1185151867
--############################ :)hack all asshole things:)
----------------------------------------------------------
```

### Example Pics

![](/showpics/show.jpg)

![](/showpics/show1.jpg)


## Usage

``` bash
----------------------------------------------------------
[+] please choose your choice to encode or decode strings:
[+] usage: [your string to convert + choice number]
[+] list of choices:
----------------------------------------------------------
```

#### Example

## En/Dedode a string without spaces using ECC Encryption

 - first generate ecc public and private key

``` bash
n casdc 9999
- you choose [n]
- {your string [casdc], your choice [9999]}
-- Generating ECC public and private keys......
-- generat ECC public and private key successful......
-- your ECC public key is:
 [-----BEGIN  WUMAN ECC PUBLIC KEY -----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKKcMkz7SfPBUXpsDMdkFaZnYnQJX
QCCF5p90uwIaxXxmJw6aAwIrsNvp/7oPDM2YfD0efFhHB4lbKsdR5WsV0Q==
-----END  WUMAN ECC PUBLIC KEY -----
]
------------------------------------------------------
-- your ECC private key is:
 [-----BEGIN  WUMAN ECC PRIVATE KEY -----
MHcCAQEEIH4OwCsvWhJGfSa6jestEaEEW/92rynOKvkq6t8glExooAoGCCqGSM49
AwEHoUQDQgAEKKcMkz7SfPBUXpsDMdkFaZnYnQJXQCCF5p90uwIaxXxmJw6aAwIr
sNvp/7oPDM2YfD0efFhHB4lbKsdR5WsV0Q==
-----END  WUMAN ECC PRIVATE KEY -----
]
```

 - then input your string to encode

``` bash
n 我草泥马 38
- you choose [n]
- {your string [我草泥马], your choice [38]}
-- Reading eccpublic key from eccpublic.pem...
-- eccpublic key:
 [-----BEGIN  WUMAN ECC PUBLIC KEY -----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKKcMkz7SfPBUXpsDMdkFaZnYnQJX
QCCF5p90uwIaxXxmJw6aAwIrsNvp/7oPDM2YfD0efFhHB4lbKsdR5WsV0Q==
-----END  WUMAN ECC PUBLIC KEY -----
]
[+] Beginning ECC Encryption......
- start writing ECC encrypted data to ecc-encrypted.txt...
- convert plaintext [我草泥马] to ECC hex encryption result [046210648396eadeec655a5e9e72f15ad49f140df0f04a825b499b902f471997b3b5f95b407d006441483bd2caf9717bb8a985457ffd08e59cb5ff65a68402a807b5c959953ac3c1ea17127a9aae06dddbb540cc43218ca6b100e15c3631d1e7155728b5171c1235bd6abe676732aa03268976e657a9a16e3a26678891]
-----------------ecc encryption over-----------------
```

 - then decode the encrypted text to plaintext

``` bash
n casd 39
- you choose [n]
- {your string [casd], your choice [39]}
-- Reading eccprivate key from eccprivate.pem...
-- eccprivate key:
 [-----BEGIN  WUMAN ECC PRIVATE KEY -----
MHcCAQEEIH4OwCsvWhJGfSa6jestEaEEW/92rynOKvkq6t8glExooAoGCCqGSM49
AwEHoUQDQgAEKKcMkz7SfPBUXpsDMdkFaZnYnQJXQCCF5p90uwIaxXxmJw6aAwIr
sNvp/7oPDM2YfD0efFhHB4lbKsdR5WsV0Q==
-----END  WUMAN ECC PRIVATE KEY -----
]
[+] Beginning ECC Decryption......
[+] Reading byte ecc encrypted data from ecc-encrypted.txt...
- convert ecc encrypted byte data from ecc-encrypted.txt to plaintext: [我草泥马]
-----------------ecc decryption over-----------------
```

## En/Dedode a string with spaces include using ECC Encryption

 - first generate ecc public and private key

``` bash
n casdc 9999
- you choose [n]
- {your string [casdc], your choice [9999]}
-- Generating ECC public and private keys......
-- generat ECC public and private key successful......
-- your ECC public key is:
 [-----BEGIN  WUMAN ECC PUBLIC KEY -----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKKcMkz7SfPBUXpsDMdkFaZnYnQJX
QCCF5p90uwIaxXxmJw6aAwIrsNvp/7oPDM2YfD0efFhHB4lbKsdR5WsV0Q==
-----END  WUMAN ECC PUBLIC KEY -----
]
------------------------------------------------------
-- your ECC private key is:
 [-----BEGIN  WUMAN ECC PRIVATE KEY -----
MHcCAQEEIH4OwCsvWhJGfSa6jestEaEEW/92rynOKvkq6t8glExooAoGCCqGSM49
AwEHoUQDQgAEKKcMkz7SfPBUXpsDMdkFaZnYnQJXQCCF5p90uwIaxXxmJw6aAwIr
sNvp/7oPDM2YfD0efFhHB4lbKsdR5WsV0Q==
-----END  WUMAN ECC PRIVATE KEY -----
]
```

 - then input your string to encode

``` bash
y 我 操 你 妈妈
- you choose [y]
- {your string [我 操 你 妈妈
]}
38
- {your choice [38]}
-- Reading eccpublic key from eccpublic.pem...
-- eccpublic key:
 [-----BEGIN  WUMAN ECC PUBLIC KEY -----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKKcMkz7SfPBUXpsDMdkFaZnYnQJX
QCCF5p90uwIaxXxmJw6aAwIrsNvp/7oPDM2YfD0efFhHB4lbKsdR5WsV0Q==
-----END  WUMAN ECC PUBLIC KEY -----
]
[+] Beginning ECC Encryption......
- start writing ECC encrypted data to ecc-encrypted.txt...
- convert plaintext [我 操 你 妈妈
] to ECC hex encryption result [0499173f0b7246278597bb1268ba64da228b6e447ea184dfa8c14277fff6c7da170cd24acf341ae2856137c90c00b495573484dd0bc133aae1a5540a17fcda9dd37b47d037f1410acc6b4ebcaa47ae18fd1b23bcc47cce5fa27b8746a1143908b9bab8cdea55d76ffc9f82e88ef2345240f7d10dde9962967bd6077c3e7f8023eb9e06b658]
-----------------ecc encryption over-----------------
```

 - then decode the encrypted text to plaintext

``` bash
y casd
- you choose [y]
- {your string [casd
]}
39
- {your choice [39]}
-- Reading eccprivate key from eccprivate.pem...
-- eccprivate key:
 [-----BEGIN  WUMAN ECC PRIVATE KEY -----
MHcCAQEEIH4OwCsvWhJGfSa6jestEaEEW/92rynOKvkq6t8glExooAoGCCqGSM49
AwEHoUQDQgAEKKcMkz7SfPBUXpsDMdkFaZnYnQJXQCCF5p90uwIaxXxmJw6aAwIr
sNvp/7oPDM2YfD0efFhHB4lbKsdR5WsV0Q==
-----END  WUMAN ECC PRIVATE KEY -----
]
[+] Beginning ECC Decryption......
[+] Reading byte ecc encrypted data from ecc-encrypted.txt...
- convert ecc encrypted byte data from ecc-encrypted.txt to plaintext: [我 操 你 妈妈
]
-----------------ecc decryption over-----------------
```

- other en/decryption method are just like this

#### Support Encryption and decryption algorithm 

 - 1. base64 encode
 - 2. base64 decode
 - 3. Aes cbc model encode
 - 4. Aes cbc model decode
 - 5. Aes ecb model encode
 - 6. Aes ecb model decode
 - 7. Aes cfb model encode
 - 8. Aes cfb model decode
 - 9. hex encode (ASCII hex)
 - 10. hex decode (ASCII hex)
 - 11. md5 encode (md5($pass.$salt);Joomia)
 - 12. sha1 encode
 - 13. hmac encode (md5)
 - 14. sha256 encode
 - 15. hmac-sha1 encode
 - 17. hmac-sha512 encode
 - 18. Base64Url Safe encode <not contain ('/','+');replaced by ('_','-');('=') removed>
 - 19. Base64Url Safe decode
 - 20. des Ecb encryption
 - 21. des Ecb decryption
 - 22. des Cbc encryption
 - 23. des Cbc decryption
 - 24. 3des Cbc encryption
 - 25. 3des Cbc decryption
 - 26. Ripemd160 encryption
 - 27. 3des Ecb encryption
 - 28. 3des Ecb decryption
 - 29. Rc4 encryption
 - 30. AzDG encryption
 - 31. AzDG decryption
 - 32. Aes CTR encryption
 - 33. Aes CTR decryption
 - 34. PBKDF2 encryption (set <passwdrd, salt, iter, keylen, hash> to strong encrypt data)
 - 999. [--Generate Rsa Public and Private Key :)--]
 - 35. RSA hex formate encryption
 - 36. RSA hex formate decryption
 - 37. RSA sign confirm
 - 9999. [ECC Key generate] --(bitcoin and ID card ... used)--[elliptic.P256() used]
 - 38. ECC Encryption --(bitcoin and ID card ... used)--[elliptic.P256() used]
 - 39. ECC Decryption --(bitcoin and ID card ... used)--[elliptic.P256() used]
 - 40. ECC sign confirm --(bitcoin and ID card ... used)--[elliptic.P256() used]
 - 41. Blowfish Ecb Encryption
 - 42. Blowfish Ecb Decryption
 - 43. Md4 encryption
 - 44. Aes Gcm Encryption [Ethereum Whisper protocol used]
 - 45. Aes Gcm Decryption [Ethereum Whisper protocol used]
 - 46. des Cfb encryption
 - 47. des Cfb decryption
 - 48. AES OFB Encryption
 - 49. AES OFB Decryption
 - 50. des Ctr encryption
 - 51. des Ctr decryption
 - 52. des Ofb encryption
 - 53. des Ofb decryption
 - 54. Elliptic Curve Digital Signature Verified
 - 55. Vertfied pub key types
 - 56. HKDF encryption
 - 57. base32 encryption
 - 58. base32 decryption
 - 59. nacl box encryption and decryption
 - 60. nacl secretbox encryption and decryption
 - 61. scrypt encryption [Bitcoin used strong encryption]
 - 62. Shake256 encryption
 - 63. Caesar encryption
 - 64. Caesar decryption
 - 65. hex dump

### 优点特色

 - 支持多达65种加解密算法
 - 彩色输出美化
 - 持续添加更多算法支持

### 注意
 - 如果工具打开报错请把flag.txt和go build生成的goendecoder.exe放在同一目录下即可
 - 有任何问题请联系qq:1185151867 :)

:) enjoy it ! :)