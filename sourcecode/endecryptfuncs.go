package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/thinkoner/openssl"
	"golang.org/x/crypto/blowfish"
)

//明文补码算法pkcs5（支持aes和des同时调用）
func pkcs5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

//明文减码算法pkcs5（支持aes和des同时调用）
func pkcs5UnPadding(origindata []byte) []byte {
	length := len(origindata)
	unpadding := int(origindata[length-1])
	return origindata[:(length - unpadding)]
}

//明文补码算法pkcs7（支持aes和des同时调用）
func pkcs7Padding(ciphertext []byte) []byte {
	padding := aes.BlockSize - len(ciphertext)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

//明文减码算法pkcs7（支持aes和des同时调用）
func pkcs7UnPadding(plainText []byte) []byte {
	length := len(plainText)
	unpadding := int(plainText[length-1])
	return plainText[:(length - unpadding)]
}

func generateKey(key []byte) (genKey []byte) {
	genKey = make([]byte, 16)
	copy(genKey, key)
	for i := 16; i < len(key); {
		for j := 0; j < 16 && i < len(key); j, i = j+1, i+1 {
			genKey[j] ^= key[i]
		}
	}
	return genKey
}

//0填充算法
func ZeroPadding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(ciphertext, padtext...)
}

//去0填充算法
func ZeroUnPadding(origindata []byte) []byte {
	return bytes.TrimFunc(origindata,
		func(r rune) bool {
			return r == rune(0)
		})
}

func desEcbEncrypt(text string, key []byte) (string, error) {
	src := []byte(text)
	block, err := des.NewCipher(key)
	if err != nil {
		return "", err
	}
	bs := block.BlockSize()
	src = ZeroPadding(src, bs)
	if len(src)%bs != 0 {
		return "", errors.New("Need a multiple of the blocksize")
	}
	out := make([]byte, len(src))
	dst := out
	for len(src) > 0 {
		block.Encrypt(dst, src[:bs])
		src = src[bs:]
		dst = dst[bs:]
	}
	return hex.EncodeToString(out), nil
}

func desEcbDecrypt(decrypted string, key []byte) (string, error) {
	src, err := hex.DecodeString(decrypted)
	if err != nil {
		return "", err
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return "", err
	}
	out := make([]byte, len(src))
	dst := out
	bs := block.BlockSize()
	if len(src)%bs != 0 {
		return "", errors.New("crypto/cipher: input not full blocks")
	}
	for len(src) > 0 {
		block.Decrypt(dst, src[:bs])
		src = src[bs:]
		dst = dst[bs:]
	}
	out = ZeroUnPadding(out)
	return string(out), nil
}

func desCbcEncrypt(src, key string) string {
	data := []byte(src)
	keyByte := []byte(key)
	block, err := des.NewCipher(keyByte)
	if err != nil {
		panic(err)
	}
	data = pkcs5Padding(data, block.BlockSize())
	iv := keyByte //用密匙作为向量
	mode := cipher.NewCBCEncrypter(block, iv)
	out := make([]byte, len(data))
	mode.CryptBlocks(out, data)
	return fmt.Sprintf("%X", out)
}

func desCbcDecrypt(src, key string) string {
	keyByte := []byte(key)
	data, err := hex.DecodeString(src)
	if err != nil {
		panic(err)
	}
	block, err := des.NewCipher(keyByte)
	if err != nil {
		panic(err)
	}
	iv := keyByte //将密匙作为向量
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(data))
	mode.CryptBlocks(plaintext, data)
	plaintext = pkcs5UnPadding(plaintext)
	return string(plaintext)
}

func tripledesCbcEncrypt(origindata, key []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	origindata = pkcs5Padding(origindata, block.BlockSize())
	//origindata = ZeroPadding(origindata, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key[:8])
	crypted := make([]byte, len(origindata))
	blockMode.CryptBlocks(crypted, origindata)
	return crypted, nil
}

func tripledesCbcDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key[:8])
	origindata := make([]byte, len(crypted))
	//origindata := crypted
	blockMode.CryptBlocks(origindata, crypted)
	origindata = pkcs5UnPadding(origindata)
	//origindata = ZeroUnPadding(origindata)
	return origindata, nil
}

func aesEncryptcbc(origindata []byte, key []byte) (encrypted []byte) {
	block, _ := aes.NewCipher(key)
	blockSize := block.BlockSize()
	origindata = pkcs5Padding(origindata, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	encrypted = make([]byte, len(origindata))
	blockMode.CryptBlocks(encrypted, origindata)
	return encrypted
}

func aesDecryptcbc(origindata []byte, key []byte) (decrypted []byte) {
	block, _ := aes.NewCipher(key)
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	decrypted = make([]byte, len(origindata))
	blockMode.CryptBlocks(decrypted, origindata)
	decrypted = pkcs5UnPadding(decrypted)
	return decrypted
}

func aesEncryptecb(origindata []byte, key []byte) (encrypted []byte) {
	cipher, _ := aes.NewCipher(generateKey(key))
	length := (len(origindata) + aes.BlockSize) / aes.BlockSize
	plain := make([]byte, length*aes.BlockSize)
	copy(plain, origindata)
	pad := byte(len(plain) - len(origindata))
	for i := len(origindata); i < len(plain); i++ {
		plain[i] = pad
	}
	encrypted = make([]byte, len(plain))
	for bs, be := 0, cipher.BlockSize(); bs <= len(origindata); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Encrypt(encrypted[bs:be], plain[bs:be])
	}
	return encrypted
}

func aesDecryptecb(origindata []byte, key []byte) (decrypted []byte) {
	cipher, _ := aes.NewCipher(generateKey(key))
	decrypted = make([]byte, len(origindata))
	for bs, be := 0, cipher.BlockSize(); bs < len(origindata); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Decrypt(decrypted[bs:be], origindata[bs:be])
	}
	trim := 0
	if len(decrypted) > 0 {
		trim = len(decrypted) - int(decrypted[len(decrypted)-1])
	}
	return decrypted[:trim]
}

func aesEncryptcfb(origindata []byte, key []byte) (encrypted []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	encrypted = make([]byte, aes.BlockSize+len(origindata))
	iv := encrypted[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(encrypted[aes.BlockSize:], origindata)
	return encrypted
}

func aesDecryptcfb(origindata []byte, key []byte) (decrypted []byte) {
	block, _ := aes.NewCipher(key)
	if len(origindata) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := origindata[:aes.BlockSize]
	origindata = origindata[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(origindata, origindata)
	return origindata
}

func AZDGcipherencode(sourceText string) string {
	h.Write([]byte(azdgcipher))
	cipherHash := fmt.Sprintf("%x", h.Sum(nil))
	h.Reset()
	inputData := []byte(sourceText)
	loopCount := len(inputData)
	outData := make([]byte, loopCount)
	for i := 0; i < loopCount; i++ {
		outData[i] = inputData[i] ^ cipherHash[i%32]
	}
	return fmt.Sprintf("%s", outData)
}

func AZDGencode(sourceText string) string {
	h.Write([]byte(time.Now().Format("2006-01-02 16:34:01")))
	noise := fmt.Sprintf("%x", h.Sum(nil))
	h.Reset()
	inputData := []byte(sourceText)
	loopCount := len(inputData)
	outData := make([]byte, loopCount*2)
	for i, j := 0, 0; i < loopCount; i, j = i+1, j+1 {
		outData[j] = noise[i%32]
		j++
		outData[j] = inputData[i] ^ noise[i%32]
	}
	return base64.StdEncoding.EncodeToString([]byte(AZDGcipherencode(fmt.Sprintf("%s", outData))))
}

func AZDGdecode(sourceText string) string {
	buf, err := base64.StdEncoding.DecodeString(sourceText)
	if err != nil {
		fmt.Println("decode(%q) failed: %v\n", sourceText, err)
		return ""
	}
	inputData := []byte(AZDGcipherencode(fmt.Sprintf("%s", buf)))
	loopCount := len(inputData)
	outData := make([]byte, loopCount)
	for i, j := 0, 0; i < loopCount; i, j = i+2, j+1 {
		outData[j] = inputData[i] ^ inputData[i+1]
	}
	return fmt.Sprintf("%s", outData)
}

func BlowfishECBEncrypt(src, key string) ([]byte, error) {
	block, err := blowfish.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	if src == "" {
		return nil, errors.New("plaintext empty")
	}
	ecb := openssl.NewECBEncrypter(block)
	content := []byte(src)
	content = pkcs5Padding(content, block.BlockSize())
	crypted := make([]byte, len(content))
	ecb.CryptBlocks(crypted, content)
	return crypted, nil
}

func BlowfishECBDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := blowfish.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	blockMode := openssl.NewECBDecrypter(block)
	origidata := make([]byte, len(crypted))
	blockMode.CryptBlocks(origidata, crypted)
	origidata = pkcs5UnPadding(origidata)
	return origidata, nil
}

func caesarEn(str string, step rune) string {
	// 计算要位移的多少位
	// 一共可以移动26位，那么第26次和第0次就是一样的
	step = step % 26 // 这个必须，虽然要循环的次数只和明文长度有关，与位移长度没有关系，但是害怕+step之后ASCC密码不在范围内
	if step <= 0 {
		return str
	}

	// 将字符串转换为明文字符切片
	str_slice := []rune(str)
	// 密文切片
	dst_slice := str_slice

	// 循环明文字符切片
	for i := 0; i < len(str_slice); i++ {
		dst_slice[i] = str_slice[i] + step

		if dst_slice[i] > 90 && dst_slice[i] < 97 {
			dst_slice[i] = dst_slice[i] - 90 + 64
		} else if dst_slice[i] > 122 {
			dst_slice[i] = dst_slice[i] - 122 + 96
		}

	}

	return string(dst_slice)
} //凯撒密码加密

func caesarDe(str string, step rune) string {
	step = step % 26
	if step <= 0 {
		return str
	}

	// 准备密文切片
	str_slice := []rune(str)

	// 准备返回的明文切片
	res_slice := str_slice

	// 循环明文
	for i := 0; i < len(str_slice); i++ {
		res_slice[i] = str_slice[i] - step
		if res_slice[i] < 65 {
			res_slice[i] = res_slice[i] - 64 + 90
		} else if res_slice[i] > 90 && res_slice[i] < 97 {
			res_slice[i] = res_slice[i] - 96 + 122
		}
	}

	return string(res_slice)
} //凯撒密码解密
