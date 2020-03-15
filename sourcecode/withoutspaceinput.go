package main

import (
	"bytes"

	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/jcmturner/gofork/x/crypto/pbkdf2"
	"github.com/thinkoner/openssl"
	"github.com/wumansgy/goEncrypt"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
)

func withoutspacestring() {
	fmt.Scanf("%s %d", &origindata, &choice)
	color.Magenta("- {your string [%s], your choice [%d]}\n", origindata, choice)
	time.Sleep(time.Second * 2)
	switch choice {
	case 1:
		//base64encode
		color.HiRed("----------------------------------------")
		color.HiRed("[+] Please wait to convert your string to base64encode string:")
		color.HiRed("----------------------------------------")
		encodedata := base64Encode([]byte(origindata))
		color.HiBlue("[+] string [%s] base64encode result is: [%s]\n", origindata, encodedata)
		color.HiRed("---------------encode over--------------")
	case 2:
		//base64decode
		color.HiRed("----------------------------------------")
		color.HiRed("[+] Please wait to base64decode your string:")
		color.HiRed("----------------------------------------")
		decodedata, err := base64Decode([]byte(origindata))
		if err != nil {
			color.HiRed(err.Error())
		}
		color.HiBlue("[+] string [%s] base64decode result is: [%s]\n", origindata, decodedata)
		color.HiRed("---------------decode over--------------")
	case 3:
		//Aes cbc encode model
		color.HiRed("- The default key is [1111111111111111], you can change the key by yourself")
		color.HiRed("- AES only supports key sizes of 16, 24 or 32 bytes")
		color.HiRed("-------------------------------------------------")
		input := []byte(origindata)
		encrypted := aesEncryptcbc(input, key)
		color.HiBlue("[+] writing encrypted data to aes-cbc-encrypted.txt......")
		writedata := ioutil.WriteFile("aes-cbc-encrypted.txt", encrypted, 0777)
		if writedata != nil {
			panic(writedata)
		}
		color.HiBlue("- string [%s] convert to aes cbc encrypt hex result [%x]\n", input, encrypted)
		color.HiRed("----------------aes cbc encode over------------------")
	case 4:
		//Aes cbc decode model
		color.HiRed("- The default key is [1111111111111111], you can change the key by yourself")
		color.HiRed("- AES only supports key sizes of 16, 24 or 32 bytes")
		color.HiRed("- Reading AES CBC Encrypted data from aes-cbc-encrypted.txt......")
		readdata, err := ioutil.ReadFile("aes-cbc-encrypted.txt")
		if err != nil {
			panic(err)
		}
		decrypted := aesDecryptcbc(readdata, key)
		color.HiBlue("-------------------------------------------------")
		color.HiBlue("- aes cbc encrypted file aes-cbc-encrypted.txt convert to plaintext [%s]\n", decrypted)
		color.HiBlue("----------------aes cbc decode over------------------")
	case 5:
		color.HiRed("- The default key is [1111111111111111], you can change the key by yourself")
		color.HiRed("- AES only supports key sizes of 16, 24 or 32 bytes")
		input := []byte(origindata)
		encrypted := aesEncryptecb(input, key)
		color.HiRed("[+] writing encrypted data to aes-ecb-encrypted.txt......")
		writedata := ioutil.WriteFile("aes-ecb-encrypted.txt", encrypted, 0777)
		if writedata != nil {
			panic(writedata)
		}
		color.HiBlue("-----------------------------------------------------")
		color.HiBlue("- convert [%s] to aes ecb encrypt hex result [%x]\n", input, encrypted)
		color.HiBlue("----------------aes ecb encode over------------------")
	case 6:
		color.HiRed("- The default key is [1111111111111111], you can change the key by yourself")
		color.HiRed("- AES only supports key sizes of 16, 24 or 32 bytes")
		color.HiRed("- Reading AES ECB Encrypted data from aes-ecb-encrypted.txt......")
		readdata, err := ioutil.ReadFile("aes-ecb-encrypted.txt")
		if err != nil {
			fmt.Println(err)
		}
		decrypted := aesDecryptecb(readdata, key)
		color.HiBlue("- aes ecb encrypted file aes-ecb-encrypted.txt convert to plaintext [%s]\n", decrypted)
		color.HiBlue("----------------aes ecb decode over------------------")
	case 7:
		color.HiRed("- The default key is [1111111111111111], you can change the key by yourself")
		color.HiRed("- AES only supports key sizes of 16, 24 or 32 bytes")
		input := []byte(origindata)
		encrypted := aesEncryptcfb(input, key)
		color.HiRed("[+] writing encrypted data to aes-cfb-encrypted.txt......")
		writedata := ioutil.WriteFile("aes-cfb-encrypted.txt", encrypted, 0777)
		if writedata != nil {
			panic(writedata)
		}
		color.HiBlue("-----------------------------------------------------")
		color.HiBlue("- convert [%s] to aes cfb encrypt hex result [%x]\n", input, encrypted)
		color.HiBlue("----------------aes cfb encode over------------------")
	case 8:
		color.HiRed("- The default key is [1111111111111111], you can change the key by yourself")
		color.HiRed("- AES only supports key sizes of 16, 24 or 32 bytes")
		color.HiRed("-----------------------------------------------------")
		readdata, err := ioutil.ReadFile("aes-cfb-encrypted.txt")
		if err != nil {
			fmt.Println(err)
		}
		decrypted := aesDecryptcfb(readdata, key)
		color.HiBlue("- aes cfb encrypted file aes-cfb-encrypted.txt convert to plaintext [%s]\n", decrypted)
		color.HiBlue("----------------aes cfb decode over------------------")
	case 9:
		color.HiRed("-------------------------------------")
		getstring := hexEncode([]byte(origindata))
		color.HiRed("[+]convert string [%s] to ASCII hex string [%s]\n", origindata, getstring)
		color.HiRed("-------------------------------------")
	case 10:
		color.HiRed("-------------------------------------")
		getstring, err := hexDecode([]byte(origindata))
		if err != nil {
			fmt.Println(err.Error())
		}
		color.HiRed("[+]convert ASCII hex string [%s] to string [%s]\n", origindata, getstring)
		color.HiRed("-------------------------------------")
	case 11:
		md5Ctx := md5.New()
		md5Ctx.Write([]byte(origindata))
		cipherStr := md5Ctx.Sum(nil)
		encryptedData := hex.EncodeToString((cipherStr))
		color.HiBlue("- [%s] encoded to {md5($pass.$salt);Joomia} string [%s]\n", origindata, encryptedData)
	case 12:
		sha1 := sha1.New()
		sha1.Write([]byte(origindata))
		color.HiBlue("- [%s] encode to sha1 string [%s]", origindata, hex.EncodeToString(sha1.Sum([]byte(""))))
	case 13:
		color.HiBlue("- The default key is [1111111111111111], you can change the key by yourself")
		hmac := hmac.New(md5.New, []byte(key))
		hmac.Write([]byte(origindata))
		color.HiBlue("- [%s] encode to md5 hmac string [%s]", origindata, hex.EncodeToString(hmac.Sum([]byte(""))))
	case 14:
		encodedata := sha256.Sum256([]byte(origindata))
		color.HiBlue("- [%s] encode to sha256 string [%x]", origindata, encodedata)
	case 15:
		color.HiRed("- The default key is [1111111111111111], you can change the key by yourself")
		mac := hmac.New(sha1.New, []byte(key))
		mac.Write([]byte(origindata))
		color.HiRed("- [%s] encode to hmac-sha1 string [%s]", origindata, hex.EncodeToString(mac.Sum(nil)))
	case 16:
		color.HiRed("- The default key is [1111111111111111], you can change the key by yourself")
		m := hmac.New(sha256.New, []byte(key))
		m.Write([]byte(origindata))
		color.HiRed("- [%s] encode to hmac-sha256 string [%s]", origindata, hex.EncodeToString(m.Sum(nil)))
	case 17:
		color.HiRed("- The default key is [1111111111111111], you can change the key by yourself")
		m := hmac.New(sha512.New, []byte(key))
		m.Write([]byte(origindata))
		color.HiRed("- [%s] encode to hmac-sha512 string [%s]", origindata, hex.EncodeToString(m.Sum(nil)))
	case 18:
		bytearr := base64.StdEncoding.EncodeToString([]byte(origindata))
		safeurl := strings.Replace(string(bytearr), "/", "_", -1)
		safeurl = strings.Replace(safeurl, "+", "-", -1)
		safeurl = strings.Replace(safeurl, "=", "", -1)
		color.HiYellow("- [%s] encode to safe base64url string [%s]", origindata, safeurl)
	case 19:
		data := string([]byte(origindata))
		//fmt.Println(data)
		var missing = (4 - len(data)%4) % 4
		data += strings.Repeat("=", missing)
		res, err := base64.URLEncoding.DecodeString(data)
		if err != nil {
			fmt.Println(err.Error())
		}
		//fmt.Println("- decode base64urlsafe is :", string(res), err)
		color.HiYellow("- decode safe base64url string [%s] to plaintext [%s]", origindata, string(res))
	case 20:
		color.HiYellow("- DES only supports key sizes 8 bytes")
		key := []byte("11111111")
		color.HiYellow("- your default key is: [%s]", color.RedString(string(key)))
		input := string([]byte(origindata))
		strEncrypted, err := desEcbEncrypt(input, key)
		if err != nil {
			log.Fatal(err)
		}
		byteEncode := []byte(strEncrypted)
		color.HiCyan("[+] writing encrypted data to des-ecb-encrypted.txt......")
		writedata := ioutil.WriteFile("des-ecb-encrypted.txt", byteEncode, 0777)
		if writedata != nil {
			panic(writedata)
		}
		color.HiCyan("- [%s] convert to des Ecb encryption string [%s]\n", origindata, strEncrypted)
		color.HiCyan("--------des Ecb encode over----------")
	case 21:
		color.HiYellow("- DES only supports key sizes 8 bytes")
		key := []byte("11111111")
		color.HiYellow("- your default key is: [%s]", color.RedString(string(key)))
		readdata, err := ioutil.ReadFile("des-ecb-encrypted.txt")
		if err != nil {
			fmt.Println(err)
		}
		strDecrypted, err := desEcbDecrypt(string(readdata), key)
		if err != nil {
			log.Fatal(err)
		}
		color.HiCyan("- des Ecb encryption file des-ecb-encrypted.txt convert to plaintext [%s]\n", strDecrypted)
		color.HiCyan("--------des Ecb decode over----------")
	case 22:
		color.HiYellow("- DES only supports key sizes 8 bytes")
		key := string("11111111")
		color.HiYellow("- your default key is: [%s]", color.RedString(key))
		data := string([]byte(origindata))
		encryptdata := desCbcEncrypt(data, key)
		color.HiYellow("[+] writing encrypted data to des-cbc-encrypted.txt......")
		bytedata := []byte(encryptdata)
		writedata := ioutil.WriteFile("des-cbc-encrypted.txt", bytedata, 0777)
		if writedata != nil {
			panic(writedata)
		}
		color.HiRed("- encode [%s] to des cbc encryption [%s]\n", origindata, encryptdata)
		color.HiRed("--------des Cbc encode over----------")
	case 23:
		color.HiYellow("- DES only supports key sizes 8 bytes")
		key := string("11111111")
		color.HiYellow("- your default key is: [%s]", color.RedString(key))
		readdata, err := ioutil.ReadFile("des-cbc-encrypted.txt")
		if err != nil {
			fmt.Println(err)
		}
		data := string(readdata)
		decryptdata := desCbcDecrypt(data, key)
		color.HiRed("- decode des cbc encryption file des-cbc-encrypted.txt to plaintext [%s]\n", decryptdata)
		color.HiRed("--------des Cbc decode over----------")
	case 24:
		color.HiYellow("- 3DES supports key size is 8*n bytes,like 24 or 32 bytes")
		key := []byte("111111111111111111111111")
		color.HiYellow("- your default key is: [%s]", color.RedString(string(key)))
		data := []byte(origindata)
		encryptdata, err := tripledesCbcEncrypt(data, key)
		if err != nil {
			panic(err)
		}
		color.HiRed("[+] writing encrypted data to 3des-cbc-encrypted.txt......")
		writedata := ioutil.WriteFile("3des-cbc-encrypted.txt", encryptdata, 0777)
		if writedata != nil {
			panic(writedata)
		}
		color.HiRed("- encode [%s] to 3des cbc hex encryption [%x]\n", origindata, encryptdata)
		color.HiRed("--------3des Cbc encode over----------")
	case 25:
		color.HiYellow("- 3DES supports key size is 8*n bytes,like 24 or 32 bytes")
		key := []byte("111111111111111111111111")
		color.HiYellow("- your default key is: [%s]", color.RedString(string(key)))
		readdata, err := ioutil.ReadFile("3des-cbc-encrypted.txt")
		if err != nil {
			fmt.Println(err)
		}
		decryptdata, err := tripledesCbcDecrypt(readdata, key)
		if err != nil {
			panic(err)
		}
		color.HiRed("- decode 3des cbc hex encryption file 3des-cbc-encrypted.txt to plaintext [%s]\n", decryptdata)
		color.HiRed("--------3des Cbc decode over----------")
	case 26:
		hash := ripemd160.New()
		getdata := []byte(origindata)
		hash.Write(getdata)
		color.HiYellow("- encode [%s] to ripemd160 hex result [%x]\n", origindata, hash.Sum(nil))
		color.HiYellow("--------ripemd160 encode over---------")
	case 27:
		color.HiYellow("- 3DES supports key size is 8*n bytes,like 24 or 32 bytes")
		key := []byte("111111111111111111111111")
		color.HiYellow("- your default key is: [%s]", color.RedString(string(key)))
		data := []byte(origindata)
		encryption, err := openssl.Des3ECBEncrypt(data, key, openssl.PKCS7_PADDING)
		if err != nil {
			panic(err)
		}
		color.HiRed("[+] writing encrypted data to 3des-ecb-encrypted.txt......")
		writedata := ioutil.WriteFile("3des-ecb-encrypted.txt", encryption, 0777)
		if writedata != nil {
			panic(writedata)
		}
		color.HiRed("- encode [%s] to 3des Ecb hex encryption [%x]\n", origindata, encryption)
		color.HiRed("--------3des Ecb encode over----------")
	case 28:
		color.HiYellow("- 3DES supports key size is 8*n bytes,like 24 or 32 bytes")
		key := []byte("111111111111111111111111")
		color.HiYellow("- your default key is: [%s]", color.RedString(string(key)))
		readdata, err := ioutil.ReadFile("3des-ecb-encrypted.txt")
		if err != nil {
			fmt.Println(err)
		}
		decryption, err := openssl.Des3ECBDecrypt(readdata, key, openssl.PKCS7_PADDING)
		if err != nil {
			panic(err)
		}
		color.HiRed("- decode 3des Ecb hex encryption file 3des-ecb-encrypted.txt to plaintext [%s]\n", decryption)
		color.HiRed("--------3des Ecb decode over----------")
	case 29:
		color.HiYellow("- the default rc4 key is [1111111111111111]")
		c, err := rc4.NewCipher(key)
		if err != nil {
			panic(err)
		}
		data := []byte(origindata)
		dst := make([]byte, len(data))
		c.XORKeyStream(dst, data)
		color.HiYellow("- encode [%s] to rc4 hex encryption [%x]\n", origindata, dst)
		color.HiYellow("--------rc4 hex encode over----------")
	case 30:
		color.HiRed("- the default azdgcipher is [AzDGkey]")
		data := string([]byte(origindata))
		s := AZDGencode(data)
		color.HiRed("- encode [%s] to AzDG encryption [%s]\n", origindata, s)
		color.HiRed("--------AzDG encode over----------")
	case 31:
		color.HiRed("- the default azdgcipher is [AzDGkey]")
		data := string([]byte(origindata))
		de := AZDGdecode(data)
		color.HiRed("-----------------------------------------------")
		color.HiRed("- decode AzDG encryption [%s] to plaintext [%s] \n", origindata, de)
		color.HiRed("--------AzDG decode over----------")
	case 32:
		color.HiGreen("- The default key is [1111111111111111], you can change the key by yourself")
		color.HiGreen("- AES only supports key sizes of 16, 24 or 32 bytes")
		input := []byte(origindata)
		ctrencrypText, err := goEncrypt.AesCtrEncrypt(input, key)
		if err != nil {
			fmt.Println(err)
		}
		color.HiGreen("[+] writing encrypted data to aes-ctr-encrypted.txt......")
		writedata := ioutil.WriteFile("aes-ctr-encrypted.txt", ctrencrypText, 0777)
		if writedata != nil {
			panic(writedata)
		}
		color.HiBlue("-----------------------------------------------------")
		color.HiBlue("- convert [%s] to aes ctr encrypt hex result [%x]\n", origindata, ctrencrypText)
		color.HiBlue("----------------aes ctr encode over------------------")
	case 33:
		color.HiGreen("- The default key is [1111111111111111], you can change the key by yourself")
		color.HiGreen("- AES only supports key sizes of 16, 24 or 32 bytes")
		readdata, err := ioutil.ReadFile("aes-ctr-encrypted.txt")
		if err != nil {
			fmt.Println(err)
		}
		ctrdecrypText, err := goEncrypt.AesCtrDecrypt(readdata, key)
		if err != nil {
			fmt.Println(err)
		}
		color.HiBlue("- convert aes ctr encrypt hex result file aes-ctr-encrypted.txt to plaintext [%s]\n", ctrdecrypText)
		color.HiBlue("----------------aes ctr decode over------------------")
	case 34:
		salt := make([]byte, 32) //生成随机盐
		_, err := rand.Read(salt)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Fatal error: %s", err.Error())
			os.Exit(1)
		}
		color.HiRed("- your default random pbkdf2 salt is:", salt)
		fmt.Printf("\n")
		color.HiRed("- your default iter is 3")
		color.HiRed("- your default keylen is 64")
		color.HiRed("- your default hash type is sha512")
		color.HiRed("- you can change all those args from source code :)")
		encryptdata := pbkdf2.Key([]byte(origindata), salt, 3, 64, sha512.New)
		color.HiRed("-----------------------------------------------------")
		color.HiRed("- encode [%s] to pbkdf2 hex encryption result [%x]\n", origindata, encryptdata)
		color.HiRed("-----------------encode pbkdf2 over------------------")
	case 999:
		goEncrypt.GetRsaKey() //生成rsa公私匙文件
		color.HiGreen("-- Generating rsa public and private keys......")
		color.HiGreen("-- generat rsa public and private key successful......")
		a, err := ioutil.ReadFile("public.pem")
		if err != nil {
			panic(err)
		}
		color.HiBlue("-- your rsa public key is:\n [%s]\n", string(a))
		color.HiBlue("------------------------------------------------------")
		b, err := ioutil.ReadFile("private.pem")
		if err != nil {
			panic(err)
		}
		color.HiGreen("-- your rsa private key is:\n [%s]\n", string(b))
	case 35:
		color.HiGreen("-- Reading public key from public.pem...")
		b, err := ioutil.ReadFile("public.pem")
		if err != nil {
			panic(err)
		}
		publicKey := b
		color.HiGreen("-- public key:\n [%s]\n", string(publicKey))
		color.HiGreen("[+] Beginning Rsa Encryption......")
		//解密pem格式的公匙
		block, _ := pem.Decode(b)
		if block == nil {
			fmt.Println("public key error")
		}
		//解析公匙
		pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			panic(err)
		}
		//类型断言
		pub := pubInterface.(*rsa.PublicKey)
		inputdata := []byte(origindata)
		encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pub, inputdata)
		if err != nil {
			panic(err)
		}
		bytedata := []byte(encrypted)
		color.HiCyan("- writing encrypted bytes to file rsa-encrypted.txt......")
		writedata := ioutil.WriteFile("rsa-encrypted.txt", bytedata, 0777)
		if writedata != nil {
			panic(writedata)
		}
		color.HiCyan("- using rsa public.pem encode [%s] to rsa hex encryption [%x]\n", origindata, encrypted)
		color.HiCyan("-----------------rsa hex encryption over-----------------")
	case 36:
		color.HiGreen("-- Reading private key from private.pem...")
		a, err := ioutil.ReadFile("private.pem")
		if err != nil {
			panic(err)
		}
		privateKey := a
		color.HiGreen("-- private key:\n [%s]\n", string(privateKey))
		color.HiGreen("[+] Beginning Rsa Decryption......")
		//解密
		block, _ := pem.Decode(a)
		if block == nil {
			fmt.Println("private key error!")
		}
		//解析PKCS1格式的私匙
		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			panic(err)
		}
		//解密
		readdata, err := ioutil.ReadFile("rsa-encrypted.txt")
		if err != nil {
			fmt.Println(err)
		}
		color.HiCyan("- reading data from rsa-encrypted.txt:", readdata)
		decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, priv, readdata)
		if err != nil {
			fmt.Println(err)
		}
		color.HiCyan("- using rsa private.pem decode rsa encryption file rsa-encrypted.txt to plaintext [%s]\n", decrypted)
		color.HiCyan("-----------------rsa hex decryption over-----------------")
	case 37:
		publicpem, err := ioutil.ReadFile("public.pem")
		if err != nil {
			panic(err)
		}
		//fmt.Println(string(publicpem))
		privatepem, err := ioutil.ReadFile("private.pem")
		if err != nil {
			panic(err)
		}
		//fmt.Println(string(privatepem))
		msg := []byte("lucifer11") //默认rsa sign message
		getkey := []byte(origindata)
		signmsg, err := goEncrypt.RsaSign(getkey, privatepem)
		if err != nil {
			fmt.Println(err)
			return
		}
		color.HiGreen("- [RSA sign message is]:", hex.EncodeToString(signmsg))
		fmt.Printf("\n")
		result := goEncrypt.RsaVerifySign(msg, signmsg, publicpem)
		if result {
			color.HiBlue("- Congradulations, RSA digital sign is correct...")
		} else {
			color.HiRed("- Unfortunatly, RSA digital sign is not correct...")
		}
	case 9999:
		goEncrypt.GetEccKey() //生成ECC密匙对
		color.HiGreen("-- Generating ECC public and private keys......")
		color.HiGreen("-- generat ECC public and private key successful......")
		a, err := ioutil.ReadFile("eccpublic.pem")
		if err != nil {
			panic(err)
		}
		color.HiRed("-- your ECC public key is:\n [%s]\n", string(a))
		color.HiRed("------------------------------------------------------")
		b, err := ioutil.ReadFile("eccprivate.pem")
		if err != nil {
			panic(err)
		}
		color.HiRed("-- your ECC private key is:\n [%s]\n", string(b))
	case 38:
		color.HiGreen("-- Reading eccpublic key from eccpublic.pem...")
		b, err := ioutil.ReadFile("eccpublic.pem")
		if err != nil {
			panic(err)
		}
		publicKey := b
		color.HiGreen("-- eccpublic key:\n [%s]\n", string(publicKey))
		color.HiGreen("[+] Beginning ECC Encryption......")
		inputdata := []byte(origindata)
		encryptText, _ := goEncrypt.EccEncrypt(inputdata, publicKey)
		color.HiBlue("- start writing ECC encrypted data to ecc-encrypted.txt...")
		writedata := ioutil.WriteFile("ecc-encrypted.txt", encryptText, 0777)
		if writedata != nil {
			panic(writedata)
		}
		color.HiBlue("- convert plaintext [%s] to ECC hex encryption result [%x]\n", origindata, encryptText)
		color.HiBlue("-----------------ecc encryption over-----------------")
	case 39:
		color.HiGreen("-- Reading eccprivate key from eccprivate.pem...")
		a, err := ioutil.ReadFile("eccprivate.pem")
		if err != nil {
			panic(err)
		}
		privateKey := a
		color.HiGreen("-- eccprivate key:\n [%s]\n", string(privateKey))
		color.HiGreen("[+] Beginning ECC Decryption......")
		color.HiGreen("[+] Reading byte ecc encrypted data from ecc-encrypted.txt...")
		readdata, err := ioutil.ReadFile("ecc-encrypted.txt")
		if err != nil {
			fmt.Println(err)
		}
		decryptText, err := goEncrypt.EccDecrypt(readdata, privateKey)
		if err != nil {
			fmt.Println(err)
		}
		color.HiBlue("- convert ecc encrypted byte data from ecc-encrypted.txt to plaintext: [%s]\n", string(decryptText))
		color.HiBlue("-----------------ecc decryption over-----------------")
	case 40:
		color.HiRed("-- Reading eccpublic key from eccpublic.pem...")
		b, err := ioutil.ReadFile("eccpublic.pem")
		if err != nil {
			panic(err)
		}
		publicKey := b
		color.HiRed("-- eccpublic key:\n [%s]\n", string(publicKey))
		color.HiRed("-- Reading eccprivate key from eccprivate.pem...")
		a, err := ioutil.ReadFile("eccprivate.pem")
		if err != nil {
			panic(err)
		}
		privateKey := a
		color.HiGreen("-- eccprivate key:\n [%s]\n", string(privateKey))
		msg := []byte("lucifer11")
		getKey := []byte(origindata)
		rtext, stext, err := goEncrypt.EccSign(getKey, privateKey)
		if err != nil {
			fmt.Println(err)
		}
		color.HiGreen("- [digital ecc sign hex message is:]", hex.EncodeToString(rtext)+hex.EncodeToString(stext))
		fmt.Printf("\n")
		result := goEncrypt.EccVerifySign(msg, publicKey, rtext, stext)
		if result {
			color.HiGreen("- digital ecc sign is correct...")
		} else {
			color.HiRed("- digital ecc sign is not correct...")
		}
	case 41:
		inputdata := string(origindata)
		getKey := string(key)
		color.HiGreen("- [your default key is:]", getKey)
		enc, err := BlowfishECBEncrypt(inputdata, getKey)
		if err != nil {
			fmt.Println("-------------------err:", err)
		}
		fmt.Printf("\n")
		color.HiGreen("[+] beginning write Blowfish Ecb Encryption data to Blowfish-Ecb-Encryption.txt......")
		writedata := ioutil.WriteFile("Blowfish-Ecb-Encryption.txt", enc, 0777)
		if writedata != nil {
			panic(writedata)
		}
		color.HiRed("- convert plaintext [%s] to Blowfish-Ecb-Encryption hex result [%x]\n", origindata, enc)
		color.HiRed("-----------------Blowfish-Ecb-Encryption over-----------------")
	case 42:
		a, err := ioutil.ReadFile("Blowfish-Ecb-Encryption.txt")
		if err != nil {
			panic(err)
		}
		color.HiGreen("-- the encrypted hex text:[%x]\n", a)
		color.HiGreen("[+] Beginning Blowfish-Ecb-Decryption......")
		color.HiGreen("[+] Reading byte Blowfish-Ecb-Encryption encrypted data from Blowfish-Ecb-Encryption.txt...")
		dec, err := BlowfishECBDecrypt(a, key)
		if err != nil {
			fmt.Println("-------------------err decode:", err)
		}
		color.HiRed("- decode Blowfish-Ecb-Encryption encrypted data from Blowfish-Ecb-Encryption.txt to plaintext: [%s]\n", dec)
		color.HiRed("-----------------Blowfish-Ecb-Decryption over-----------------")
	case 43:
		h := md4.New()
		io.WriteString(h, origindata)
		color.HiRed("- convert plaintext [%s] to md4 hash string [%x]\n", origindata, h.Sum(nil))
		color.HiRed("-----------------Md4-Encryption over-----------------")
	case 44:
		plainText := []byte(origindata)
		block, err := aes.NewCipher(key)
		color.HiGreen("[+] The default key is:", string(key))
		if err != nil {
			panic(err.Error())
		}
		nonce := make([]byte, 12)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			panic(err.Error())
		} //将nonce的值取随机数并且填充,使用这个方法之后，每次解密的时候需要读取随机的nonce才能解密
		color.HiGreen("[+] beginning write random nonce to random-nonce.txt......")
		writenonce := ioutil.WriteFile("random-nonce.txt", nonce, 0777)
		if writenonce != nil {
			panic(writenonce)
		}
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			panic(err.Error())
		}
		encryptedText := aesgcm.Seal(nil, nonce, plainText, nil)
		color.HiRed("[+] beginning write AES GCM Encryption data to AES-GCM-Encryption.txt......")
		writedata := ioutil.WriteFile("AES-GCM-Encryption.txt", encryptedText, 0777)
		if writedata != nil {
			panic(writedata)
		}
		color.HiRed("- encrypt your string [%s] to AES GCM hex string [%x]\n", origindata, encryptedText)
		color.HiRed("-----------------AES-GCM-Encryption over-----------------")
	case 45:
		color.HiGreen("[+] The default key is:", string(key))
		color.HiGreen("[+] Reading byte AES-GCM-Encryption encrypted data from AES-GCM-Encryption.txt...")
		a, err := ioutil.ReadFile("AES-GCM-Encryption.txt")
		if err != nil {
			panic(err.Error())
		}
		color.HiGreen("-- the aes gcm encrypted hex text:[%x]\n", a)
		color.HiGreen("[+] Reading random nonce from random-nonce.txt...")
		b, err := ioutil.ReadFile("random-nonce.txt")
		if err != nil {
			panic(err.Error())
		}
		color.HiRed("-- the random-nonce hex text:[%x]\n", b)
		color.HiRed("[+] Beginning AES-GCM-Decryption......")

		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err.Error())
		}
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			panic(err.Error())
		}

		plainText, err := aesgcm.Open(nil, b, a, nil)
		if err != nil {
			panic(err.Error())
		}
		color.HiRed("- decode AES-GCM-Encryption data from AES-GCM-Encryption.txt to plaintext: [%s]\n", plainText)
		color.HiRed("-----------------AES-GCM-Decryption over-----------------")
	case 46:
		color.HiCyan("- DES only supports key sizes 8 bytes")
		key := []byte("11111111")
		color.HiCyan("- your default key is:", string(key))
		plaintext := []byte(origindata)
		block, err := des.NewCipher(key)
		if err != nil {
			panic(err)
		}
		ciphertext := make([]byte, des.BlockSize+len(plaintext))
		iv := ciphertext[:des.BlockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			panic(err)
		} //将iv使用随机值填充
		color.HiCyan("[+] beginning write random iv to random-iv.txt......")
		writeiv := ioutil.WriteFile("random-iv.txt", iv, 0777)
		if writeiv != nil {
			panic(writeiv)
		}
		stream := cipher.NewCFBEncrypter(block, iv)
		stream.XORKeyStream(ciphertext[des.BlockSize:], plaintext)
		color.HiRed("[+] beginning write des cfb encrypted data to des-cfb-ciphertext.txt......")
		writechiphertext := ioutil.WriteFile("des-cfb-ciphertext.txt", ciphertext, 0777)
		if writechiphertext != nil {
			panic(writechiphertext)
		}
		color.HiRed("- encode your string [%s] to des cfb hex encrypted data [%x]\n", origindata, ciphertext)
		color.HiRed("-----------------DES-CFB-Encryption over-----------------")
	case 47:
		color.HiCyan("- DES only supports key sizes 8 bytes")
		key := []byte("11111111")
		color.HiCyan("- your default key is:", string(key))
		color.HiCyan("[+] Reading byte DES-CFB-Encryption encrypted data from des-cfb-ciphertext.txt...")
		encrypttext, err := ioutil.ReadFile("des-cfb-ciphertext.txt")
		if err != nil {
			panic(err.Error())
		}
		color.HiCyan("-- the des cfb encrypted hex text:[%x]\n", encrypttext)
		color.HiCyan("[+] Reading random iv from random-iv.txt...")
		iv, err := ioutil.ReadFile("random-iv.txt")
		if err != nil {
			panic(err.Error())
		}
		color.HiCyan("-- the random-iv hex text:[%x]\n", iv)
		color.HiRed("[+] Beginning DES-CFB-Decryption......")
		block, err := des.NewCipher(key)
		if err != nil {
			panic(err)
		}
		if len(encrypttext) < des.BlockSize {
			panic("ciphertext too short")
		}
		//iv = encrypttext[:des.BlockSize]
		//encrypttext = encrypttext[des.BlockSize:]
		stream := cipher.NewCFBDecrypter(block, iv)
		stream.XORKeyStream(encrypttext, encrypttext)
		color.HiRed("- decode your des cfb hex encrypted data to plaintext: [%s]\n", encrypttext)
		color.HiRed("-----------------DES-CFB-Decryption over-----------------")
	case 48:
		color.HiGreen("- The default key is [1111111111111111], you can change the key by yourself")
		color.HiGreen("- AES only supports key sizes of 16, 24 or 32 bytes")
		plaintext := []byte(origindata)
		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		ciphertext := make([]byte, aes.BlockSize+len(plaintext))
		iv := ciphertext[:aes.BlockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			panic(err)
		} //将iv的值随机填充
		color.Red("[+] beginning write random iv to random-iv.txt......")
		writeiv := ioutil.WriteFile("random-iv.txt", iv, 0777)
		if writeiv != nil {
			panic(writeiv)
		}
		stream := cipher.NewOFB(block, iv)
		stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
		color.Red("[+] beginning write aes ofb encrypted data to aes-ofb-ciphertext.txt......")
		writechiphertext := ioutil.WriteFile("aes-ofb-ciphertext.txt", ciphertext, 0777)
		if writechiphertext != nil {
			panic(writechiphertext)
		}
		color.Red("- encode your string [%s] to aes ofb encrypted hex string [%x]\n", origindata, ciphertext)
		color.Red("-----------------AES-OFB-Encryption over-----------------")
	case 49:
		color.HiGreen("- The default key is [1111111111111111], you can change the key by yourself")
		color.HiGreen("- AES only supports key sizes of 16, 24 or 32 bytes")
		plaintext := []byte(origindata)
		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		ciphertext := make([]byte, aes.BlockSize+len(plaintext))
		iv := ciphertext[:aes.BlockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			panic(err)
		} //将iv的值随机填充

		color.HiGreen("[+] beginning write random iv to random-iv.txt......")
		writeiv := ioutil.WriteFile("random-iv.txt", iv, 0777)
		if writeiv != nil {
			panic(writeiv)
		}
		color.HiGreen("[+] Reading random iv from random-iv.txt...")
		iv, err = ioutil.ReadFile("random-iv.txt")
		if err != nil {
			panic(err.Error())
		}
		color.HiGreen("-- the random-iv hex text:[%x]\n", iv)
		stream := cipher.NewOFB(block, iv)
		stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
		color.Red("[+] beginning write aes ofb encrypted data to aes-ofb-ciphertext.txt......")
		writechiphertext := ioutil.WriteFile("aes-ofb-ciphertext.txt", ciphertext, 0777)
		if writechiphertext != nil {
			panic(writechiphertext)
		}
		color.Red("[+] Reading byte AES-OFB-Encryption encrypted data from aes-ofb-ciphertext.txt...")
		encrypttext, err := ioutil.ReadFile("aes-ofb-ciphertext.txt")
		if err != nil {
			panic(err.Error())
		}
		color.Red("-- the aes ofb encrypted hex text:[%x]\n", encrypttext)
		color.Red("[+] Beginning AES-OFB-Decryption......")
		plaintext2 := make([]byte, len(plaintext))
		stream = cipher.NewOFB(block, iv)
		stream.XORKeyStream(plaintext2, ciphertext[aes.BlockSize:])
		color.Red("-- decode the aes ofb encrypted data from aes-ofb-ciphertext.txt [%s]\n", plaintext2)
		color.Red("-----------------AES-OFB-Decryption over-----------------")
	case 50:
		color.Yellow("- The default key is [11111111], you can change the key by yourself")
		color.Yellow("- DES only supports key sizes 8 bytes")
		key := []byte("11111111")
		plaintext := []byte(origindata)
		block, err := des.NewCipher(key)
		if err != nil {
			panic(err)
		}
		ciphertext := make([]byte, des.BlockSize+len(plaintext))
		iv := ciphertext[:des.BlockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			panic(err)
		} //将iv的值随机填充
		color.Yellow("[+] beginning write random iv to random-iv.txt......")
		writeiv := ioutil.WriteFile("random-iv.txt", iv, 0777)
		if writeiv != nil {
			panic(writeiv)
		}
		stream := cipher.NewOFB(block, iv)
		stream.XORKeyStream(ciphertext[des.BlockSize:], plaintext)
		color.Yellow("[+] beginning write des ctr encrypted data to des-ctr-ciphertext.txt......")
		writechiphertext := ioutil.WriteFile("des-ctr-ciphertext.txt", ciphertext, 0777)
		if writechiphertext != nil {
			panic(writechiphertext)
		}
		color.Red("- encode your string [%s] to des ctr encrypted hex string [%x]\n", origindata, ciphertext)
		color.Red("-----------------DES-CTR-Encryption over-----------------")
	case 51:
		color.Yellow("- The default key is [11111111], you can change the key by yourself")
		color.Yellow("- DES only supports key sizes 8 bytes")
		key := []byte("11111111")
		plaintext := []byte(origindata)
		block, err := des.NewCipher(key)
		if err != nil {
			panic(err)
		}
		ciphertext := make([]byte, des.BlockSize+len(plaintext))
		iv := ciphertext[:des.BlockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			panic(err)
		} //将iv的值随机填充

		color.Yellow("[+] beginning write random iv to random-iv.txt......")
		writeiv := ioutil.WriteFile("random-iv.txt", iv, 0777)
		if writeiv != nil {
			panic(writeiv)
		}
		color.Yellow("[+] Reading random iv from random-iv.txt...")
		iv, err = ioutil.ReadFile("random-iv.txt")
		if err != nil {
			panic(err.Error())
		}
		color.Yellow("-- the random-iv hex text:[%x]\n", iv)
		stream := cipher.NewOFB(block, iv)
		stream.XORKeyStream(ciphertext[des.BlockSize:], plaintext)
		color.Yellow("[+] beginning write des ctr encrypted data to des-ctr-ciphertext.txt......")
		writechiphertext := ioutil.WriteFile("des-ctr-ciphertext.txt", ciphertext, 0777)
		if writechiphertext != nil {
			panic(writechiphertext)
		}
		color.Yellow("[+] Reading byte DES-CTR-Encryption encrypted data from des-ctr-ciphertext.txt...")
		encrypttext, err := ioutil.ReadFile("des-ctr-ciphertext.txt")
		if err != nil {
			panic(err.Error())
		}
		color.Yellow("-- the des ctr encrypted hex text:[%x]\n", encrypttext)
		color.Yellow("[+] Beginning DES-CTR-Decryption......")
		plaintext2 := make([]byte, len(plaintext))
		stream = cipher.NewOFB(block, iv)
		stream.XORKeyStream(plaintext2, ciphertext[des.BlockSize:])
		color.Red("-- decode the des ctr encrypted data from des-ctr-ciphertext.txt [%s]\n", plaintext2)
		color.Red("-----------------DES-CTR-Decryption over-----------------")
	case 52:
		color.Cyan("- The default key is [11111111], you can change the key by yourself")
		color.Cyan("- DES only supports key sizes 8 bytes")
		key := []byte("11111111")
		plaintext := []byte(origindata)
		block, err := des.NewCipher(key)
		if err != nil {
			panic(err)
		}
		ciphertext := make([]byte, des.BlockSize+len(plaintext))
		iv := ciphertext[:des.BlockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			panic(err)
		} //将iv的值随机填充
		color.Cyan("[+] beginning write random iv to random-iv.txt......")
		writeiv := ioutil.WriteFile("random-iv.txt", iv, 0777)
		if writeiv != nil {
			panic(writeiv)
		}
		stream := cipher.NewOFB(block, iv)
		stream.XORKeyStream(ciphertext[des.BlockSize:], plaintext)
		color.Cyan("[+] beginning write des ofb encrypted data to des-ofb-ciphertext.txt......")
		writechiphertext := ioutil.WriteFile("des-ofb-ciphertext.txt", ciphertext, 0777)
		if writechiphertext != nil {
			panic(writechiphertext)
		}
		color.Blue("- encode your string [%s] to des ofb encrypted hex string [%x]\n", origindata, ciphertext)
		color.Blue("-----------------DES-OFB-Encryption over-----------------")
	case 53:
		color.Cyan("- The default key is [11111111], you can change the key by yourself")
		color.Cyan("- DES only supports key sizes 8 bytes")
		key := []byte("11111111")
		plaintext := []byte(origindata)
		block, err := des.NewCipher(key)
		if err != nil {
			panic(err)
		}
		ciphertext := make([]byte, des.BlockSize+len(plaintext))
		iv := ciphertext[:des.BlockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			panic(err)
		} //将iv的值随机填充

		color.Cyan("[+] beginning write random iv to random-iv.txt......")
		writeiv := ioutil.WriteFile("random-iv.txt", iv, 0777)
		if writeiv != nil {
			panic(writeiv)
		}
		color.Cyan("[+] Reading random iv from random-iv.txt...")
		iv, err = ioutil.ReadFile("random-iv.txt")
		if err != nil {
			panic(err.Error())
		}
		color.Cyan("-- the random-iv hex text:[%x]\n", iv)
		stream := cipher.NewOFB(block, iv)
		stream.XORKeyStream(ciphertext[des.BlockSize:], plaintext)
		color.Cyan("[+] beginning write des ofb encrypted data to des-ofb-ciphertext.txt......")
		writechiphertext := ioutil.WriteFile("des-ofb-ciphertext.txt", ciphertext, 0777)
		if writechiphertext != nil {
			panic(writechiphertext)
		}
		color.Cyan("[+] Reading byte DES-OFB-Encryption encrypted data from des-ofb-ciphertext.txt...")
		encrypttext, err := ioutil.ReadFile("des-ofb-ciphertext.txt")
		if err != nil {
			panic(err.Error())
		}
		color.Cyan("-- the des ofb encrypted hex text:[%x]\n", encrypttext)
		color.Cyan("[+] Beginning DES-OFB-Decryption......")
		plaintext2 := make([]byte, len(plaintext))
		stream = cipher.NewOFB(block, iv)
		stream.XORKeyStream(plaintext2, ciphertext[des.BlockSize:])
		color.Red("-- decode the des ofb encrypted data from des-ofb-ciphertext.txt [%s]\n", plaintext2)
		color.Red("-----------------DES-OFB-Decryption over-----------------")
	case 54:
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		msg := "lucifer11"
		hash := sha256.Sum256([]byte(msg))
		veryfyhash := sha256.Sum256([]byte(origindata))

		r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
		if err != nil {
			panic(err)
		}
		color.Red("- Signature: (0x%x, 0x%x)\n", r, s)

		valid := ecdsa.Verify(&privateKey.PublicKey, veryfyhash[:], r, s)
		color.Red("- Elliptic Curve Digital Signature verified:", valid)
		fmt.Printf("\n")
		color.Red("-----------------Elliptic Curve Digital Signature verified over-----------------")
	case 55:
		color.HiMagenta("[+] Reading pub key pem...")
		pubkeytext, err := ioutil.ReadFile("public.pem")
		if err != nil {
			panic(err.Error())
		}
		color.HiMagenta("-- the pub key text:[%s]\n", pubkeytext)
		color.HiMagenta("[+] Beginning verify pub key types......")
		block, _ := pem.Decode(pubkeytext)
		if block == nil {
			panic("failed to parse PEM block containing the public key")
		}

		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			panic("failed to parse DER encoded public key: " + err.Error())
		}

		switch pub := pub.(type) {
		case *rsa.PublicKey:
			color.HiBlue("- pubkey is of type RSA:", pub)
		case *dsa.PublicKey:
			color.HiRed("- pubkey is of type DSA:", pub)
		case *ecdsa.PublicKey:
			color.HiGreen("- pubkey is of type ECDSA:", pub)
		case ed25519.PublicKey:
			color.HiYellow("- pubkey is of type Ed25519:", pub)
		default:
			panic("- unknown type of public key")
		}
		fmt.Printf("\n")
		color.Red("-----------------public key verifted over-----------------")
	case 56:
		// Underlying hash function for HMAC.
		hash := sha256.New

		// Cryptographically secure master secret.
		secret := []byte{0x00, 0x01, 0x02, 0x03}
		color.HiRed("[+] the secure master secret bytes is:", secret)
		// Non-secret salt, optional (can be nil).
		// Recommended: hash-length random value.
		salt := make([]byte, hash().Size())
		if _, err := rand.Read(salt); err != nil {
			panic(err)
		}
		fmt.Printf("\n")
		color.HiRed("[+] the random salt byte is:", salt)
		// Non-secret context info, optional (can be nil).
		info := []byte(origindata)
		fmt.Printf("\n")
		color.HiRed("[+] your input text is:", origindata)
		// Generate three 128-bit derived keys.
		hkdf := hkdf.New(hash, secret, salt, info)
		fmt.Printf("\n")
		color.HiRed("[+] hkdf is:", hkdf)
		fmt.Printf("\n")
		color.HiRed("[+] Generate three 128-bit derived keys...")
		var keys [][]byte
		for i := 0; i < 3; i++ {
			key := make([]byte, 16)
			if _, err := io.ReadFull(hkdf, key); err != nil {
				panic(err)
			}
			keys = append(keys, key)
		}

		for i := range keys {
			color.HiGreen("[+] verify the Key size {#%d time}: %v\n", i+1, !bytes.Equal(keys[i], make([]byte, 16)))
			color.HiGreen("[+] the generated key bytes is:", keys)
			fmt.Printf("\n")
		}
		color.HiGreen("-----------------HKDF encryption over-----------------")
	case 57:
		inputstrings := []byte(origindata)
		str := base32.StdEncoding.EncodeToString(inputstrings)
		color.HiGreen("[+] encode your strings [%s] to base32 encryption: [%s]\n", origindata, str)
		color.HiGreen("-----------------base32 encryption over-----------------")
	case 58:
		data, err := base32.StdEncoding.DecodeString(origindata)
		if err != nil {
			fmt.Println("error:", err)
			return
		}
		color.HiGreen("[+] decode your base32 encryption strings [%s] to plaintext: [%s]\n", origindata, string(data))
		color.HiGreen("-----------------base32 decryption over-----------------")
	case 59:
		senderPublicKey, senderPrivateKey, err := box.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		color.HiGreen("[+] the rand senderPrivateKey byte is:", *senderPrivateKey)
		recipientPublicKey, recipientPrivateKey, err := box.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		fmt.Printf("\n")
		color.HiGreen("[+] the rand recipientPublicKey byte is:", *recipientPublicKey)
		sharedEncryptKey := new([32]byte)
		fmt.Printf("\n")
		color.HiGreen("[+] the sharedEncryptKey byte is:", *sharedEncryptKey)
		box.Precompute(sharedEncryptKey, recipientPublicKey, senderPrivateKey)
		var nonce [24]byte
		if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
			panic(err)
		}
		fmt.Printf("\n")
		color.HiGreen("[+] the rand nonce byte is:", nonce)
		msg := []byte(origindata)
		fmt.Printf("\n")
		color.HiBlue("[+] your input data is: [%s]\n", origindata)
		encrypted := box.SealAfterPrecomputation(nonce[:], msg, &nonce, sharedEncryptKey)
		color.HiBlue("[+] encode your input string [%s] to nacl box hex encryption [%x]\n", origindata, encrypted)
		color.HiBlue("-----------------nacl box encryption over-----------------")
		color.HiGreen("[+] the rand senderPublicKey byte is:", *senderPublicKey)
		fmt.Printf("\n")
		color.HiGreen("[+] the rand recipientPrivateKey byte is:", *recipientPrivateKey)
		var sharedDecryptKey [32]byte
		box.Precompute(&sharedDecryptKey, senderPublicKey, recipientPrivateKey)
		fmt.Printf("\n")
		color.HiGreen("[+] the sharedDecryptKey byte is:", sharedDecryptKey)
		var decryptNonce [24]byte
		copy(decryptNonce[:], encrypted[:24])
		fmt.Printf("\n")
		color.HiGreen("[+] the decryptNonce byte is:", decryptNonce)
		decrypted, ok := box.OpenAfterPrecomputation(nil, encrypted[24:], &decryptNonce, &sharedDecryptKey)
		if !ok {
			panic("decryption error")
		}
		fmt.Printf("\n")
		color.HiRed("[+] decode your nacl box hex encryption string [%x] to plaintext [%s]\n", encrypted, decrypted)
		color.HiRed("-----------------nacl box decryption over-----------------")
	case 60:
		secretKeyBytes := key
		var secretKey [32]byte
		copy(secretKey[:], secretKeyBytes)
		color.HiYellow("[+] the secret key byte is:", secretKey)
		fmt.Printf("\n")
		var nonce [24]byte
		if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
			panic(err)
		}
		color.HiYellow("[+] the random nonce byte is:", nonce)
		fmt.Printf("\n")
		encrypted := secretbox.Seal(nonce[:], []byte(origindata), &nonce, &secretKey)
		color.HiYellow("[+] encrypt your string [%s] to nacl secretbox hex encryption [%x]\n", origindata, encrypted)
		color.HiYellow("-----------------nacl secretbox encryption over-----------------")
		var decryptNonce [24]byte
		copy(decryptNonce[:], encrypted[:24])
		fmt.Printf("\n")
		color.HiGreen("[+] the secret key byte is:", secretKey)
		fmt.Printf("\n")
		color.HiGreen("[+] the decryptNonce byte is:", decryptNonce)
		decrypted, ok := secretbox.Open(nil, encrypted[24:], &decryptNonce, &secretKey)
		if !ok {
			panic("decryption error")
		}
		fmt.Printf("\n")
		color.HiGreen("[+] decrypt your nacl secretbox hex encryption [%x] to plaintext [%s]\n", encrypted, decrypted)
		color.HiGreen("-----------------nacl secretbox decryption over-----------------")
	case 61:
		salt := key
		color.HiRed("[+] your default salt is:", string(salt))
		fmt.Printf("\n")
		dk, err := scrypt.Key([]byte(origindata), salt, 1<<15, 8, 1, 32)
		if err != nil {
			log.Fatal(err)
		}
		color.HiRed("[+] encrypt your string [%s] to scrypt hex encryption [%x]\n", origindata, dk)
		color.HiRed("-----------------scrypt encryption over-----------------")
	case 62:
		k := key
		color.HiYellow("[+] your default key is:", string(k))
		buf := []byte(origindata)
		h := make([]byte, 32)
		d := sha3.NewShake256()
		d.Write(k)
		d.Write(buf)
		d.Read(h)
		fmt.Printf("\n")
		color.HiYellow("[+] encrypt your string [%s] to Shake256 hex encryption [%x]\n", origindata, h)
		color.HiYellow("-----------------Shake256 encryption over-----------------")
	case 63:
		color.HiCyan("[+] now begining caesar encryption...")
		mingw := origindata
		miwen := caesarEn(mingw, 8) //移动8位
		fmt.Printf("\n")
		color.HiCyan("[+] encode your string [%s] (move 8 steps) to caesar Encryption [%s]\n", origindata, miwen)
		color.HiCyan("-----------------caesar encryption over-----------------")
	case 64:
		color.HiGreen("[+] now begining caesar decryption...")
		fmt.Printf("\n")
		miwen := origindata
		var i rune
		for i = 0; i < 26; i++ {
			resm := caesarDe(miwen, i)
			color.HiGreen("[+] the [%d] time decode plaintext is: [%s]\n", i, resm)
		}
		color.HiGreen("-----------------caesar decryption over-----------------")
	case 65:
		content := []byte(origindata)
		color.HiBlue("[+] turn your string [%s] to hex dump:\n[+] [%s]\n", origindata, hex.Dump(content))
		color.HiBlue("-----------------hex dump over-----------------")
	default:
		color.HiRed("...):you choice algorithm is not support or usage is not right...")

	}
}
