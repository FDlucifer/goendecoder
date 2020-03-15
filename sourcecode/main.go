package main

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"

	"github.com/fatih/color"
)

func base64Encode(src []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(src))
}

func base64Decode(src []byte) ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(src))
}

func hexEncode(src []byte) []byte {
	return []byte(hex.EncodeToString(src))
}

func hexDecode(src []byte) ([]byte, error) {
	return hex.DecodeString(string(src))
}

var (
	origindata string
	choice     int
	key        = []byte("1111111111111111")
	azdgcipher = "AzDGkey"
	h          = md5.New()
	space      string
)

func main() {
	flagtext, err := ioutil.ReadFile("flag.txt")
	if err != nil {
		panic(err.Error())
	}
	color.Magenta("----------------------------------------------------------")
	color.Blue("%s", flagtext)
	color.Magenta("----------------------------------------------------------")
	color.Cyan("%s", color.RedString("QQ 1185151867"))
	color.Red("--############################ %s", color.HiCyanString(":)hack all asshole things:)"))
	color.Magenta("----------------------------------------------------------")
	color.Yellow("[+] please choose your choice to encode or decode strings:")
	color.Yellow("[+] usage: %s", color.RedString("[your string to convert + choice number]"))
	color.Yellow("[+] list of choices:")
	color.Magenta("----------------------------------------------------------")
	color.Yellow("1. base64 encode")
	color.Yellow("2. base64 decode")
	color.Yellow("3. Aes cbc model encode")
	color.Yellow("4. Aes cbc model decode")
	color.Yellow("5. Aes ecb model encode")
	color.Yellow("6. Aes ecb model decode")
	color.Yellow("7. Aes cfb model encode")
	color.Yellow("8. Aes cfb model decode")
	color.Yellow("9. hex encode %s", color.BlueString("(ASCII hex)"))
	color.Yellow("10. hex decode %s", color.BlueString("(ASCII hex)"))
	color.Yellow("11. md5 encode %s", color.BlueString("(md5($pass.$salt);Joomia)"))
	color.Yellow("12. sha1 encode")
	color.Yellow("13. hmac encode %s", color.BlueString("(md5)"))
	color.Yellow("14. sha256 encode")
	color.Yellow("15. hmac-sha1 encode")
	color.Yellow("17. hmac-sha512 encode")
	color.Yellow("18. Base64Url Safe encode %s", color.BlueString("<not contain ('/','+');replaced by ('_','-');('=') removed>"))
	color.Yellow("19. Base64Url Safe decode")
	color.Yellow("20. des Ecb encryption")
	color.Yellow("21. des Ecb decryption")
	color.Yellow("22. des Cbc encryption")
	color.Yellow("23. des Cbc decryption")
	color.Yellow("24. 3des Cbc encryption")
	color.Yellow("25. 3des Cbc decryption")
	color.Yellow("26. Ripemd160 encryption")
	color.Yellow("27. 3des Ecb encryption")
	color.Yellow("28. 3des Ecb decryption")
	color.Yellow("29. Rc4 encryption")
	color.Yellow("30. AzDG encryption")
	color.Yellow("31. AzDG decryption")
	color.Yellow("32. Aes CTR encryption")
	color.Yellow("33. Aes CTR decryption")
	color.Yellow("34. PBKDF2 encryption %s", color.BlueString("(set <passwdrd, salt, iter, keylen, hash> to strong encrypt data)"))
	color.Red("999. [--Generate Rsa Public and Private Key :)--]")
	color.Yellow("35. RSA hex formate encryption")
	color.Yellow("36. RSA hex formate decryption")
	color.Yellow("37. RSA sign confirm")
	color.Red("9999. [ECC Key generate] %s", color.BlueString("--(bitcoin and ID card ... used)--[elliptic.P256() used]"))
	color.Yellow("38. ECC Encryption %s", color.BlueString("--(bitcoin and ID card ... used)--[elliptic.P256() used]"))
	color.Yellow("39. ECC Decryption %s", color.BlueString("--(bitcoin and ID card ... used)--[elliptic.P256() used]"))
	color.Yellow("40. ECC sign confirm %s", color.BlueString("--(bitcoin and ID card ... used)--[elliptic.P256() used]"))
	color.Yellow("41. Blowfish Ecb Encryption")
	color.Yellow("42. Blowfish Ecb Decryption")
	color.Yellow("43. Md4 encryption")
	color.Yellow("44. Aes Gcm Encryption %s", color.RedString("[Ethereum Whisper protocol used]"))
	color.Yellow("45. Aes Gcm Decryption %s", color.RedString("[Ethereum Whisper protocol used]"))
	color.Yellow("46. des Cfb encryption")
	color.Yellow("47. des Cfb decryption")
	color.Yellow("48. AES OFB Encryption")
	color.Yellow("49. AES OFB Decryption")
	color.Yellow("50. des Ctr encryption")
	color.Yellow("51. des Ctr decryption")
	color.Yellow("52. des Ofb encryption")
	color.Yellow("53. des Ofb decryption")
	color.Yellow("54. Elliptic Curve Digital Signature Verified")
	color.Yellow("55. Vertfied pub key types")
	color.Yellow("56. HKDF encryption")
	color.Yellow("57. base32 encryption")
	color.Yellow("58. base32 decryption")
	color.Yellow("59. nacl box encryption and decryption")
	color.Yellow("60. nacl secretbox encryption and decryption")
	color.Yellow("61. scrypt encryption %s", color.RedString("[Bitcoin used strong encryption]"))
	color.Yellow("62. Shake256 encryption")
	color.Yellow("63. Caesar encryption")
	color.Yellow("64. Caesar decryption")
	color.Yellow("65. hex dump")
	color.Magenta("----------------------------------------------------------")
	color.Red("[+] If your input strings includes spaces then type [y] and [with spaces strings] at after then add [your choice]...")
	color.Red("[+] if not included spaces type [n] + [your string] + [your choice]")
	color.Green("[+] please input your strings to decode or encode:")
	fmt.Scanf("%s", &space)
	color.Red("- you choose [%s]\n", space)
	if space == "y" {
		withspacestring()
	} else if space == "n" {
		withoutspacestring()
	}
}
