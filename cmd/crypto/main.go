package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/miekg/pkcs11"
	"golang.org/x/crypto/nacl/secretbox"

	awssession "github.com/aws/aws-sdk-go/aws/session"
)

const (
	keyLength   = 32
	nonceLength = 24
)

var (
	kmsClient *kms.KMS
	p11Func   = pkcs11.New("")
	session   pkcs11.SessionHandle
)

type payload struct {
	Key        []byte
	WrappedKey []byte
	Nonce      *[nonceLength]byte
	Message    []byte
}

func checkResult(ret error, message string) {
	if ret != nil {
		fmt.Printf("Problem occured during %s : %s\n", message, ret)
		p11Func.Finalize()
		os.Exit(0)
	}
}

func generateRSAKeyPair() (pkcs11.ObjectHandle, pkcs11.ObjectHandle) {
	var modBits = 2048
	exp := []byte{0x01, 0x00, 0x00, 0x00, 0x01}
	publicTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, modBits),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, exp),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "pub1"),
	}

	privateTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_MODIFIABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "priv1"),
	}
	pubKey, priKey, ret := p11Func.GenerateKeyPair(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}, publicTemplate, privateTemplate)
	checkResult(ret, "GenerateKeyPair")
	log.Println("RSA-2048 keypair generated.")
	log.Printf("   - Private Key : %d\n", priKey)
	log.Printf("   - Public Key  : %d\n", pubKey)
	return pubKey, priKey
}

func exportPubKey() {
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "pub1"),
	}

	if err := p11Func.FindObjectsInit(session, publicKeyTemplate); err != nil {
		panic(err)
	}

	pubKeySlice, _, err := p11Func.FindObjects(session, 1)
	if err != nil {
		panic(err)
	}
	if err = p11Func.FindObjectsFinal(session); err != nil {
		panic(err)
	}

	pubKey := pubKeySlice[0]
	pr, err := p11Func.GetAttributeValue(session, pubKey, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	})
	if err != nil {
		panic(err)
	}

	modulus := new(big.Int)
	bigExponent := new(big.Int)
	exponent := int(bigExponent.SetBytes(pr[1].Value).Uint64())

	rsaPub := &rsa.PublicKey{
		N: modulus.SetBytes(pr[0].Value),
		E: exponent,
	}

	pubkeyPem := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(rsaPub)}))
	log.Printf("  Public Key: \n%s\n", pubkeyPem)
	pemfile, err := os.Create("hsm_public.pem")
	if err != nil {
		panic(err)
	}
	defer pemfile.Close()

	pem.Encode(pemfile, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(rsaPub)})

}

func wrapKey(key []byte) []byte {
	pub, err := ioutil.ReadFile("hsm_public.pem")
	if err != nil {
		panic(err)
	}
	pubPem, _ := pem.Decode(pub)
	if pubPem == nil {
		log.Fatal("key is null")
	}

	var parsedKey interface{}
	var ok bool

	if parsedKey, err = x509.ParsePKCS1PublicKey(pubPem.Bytes); err != nil {
		panic(err)
	}

	var pubKey *rsa.PublicKey
	if pubKey, ok = parsedKey.(*rsa.PublicKey); !ok {
		panic(err)
	}

	encryptedBytes, err := rsa.EncryptPKCS1v15(
		rand.Reader,
		pubKey,
		key,
	)
	if err != nil {
		panic(err)
	}

	return encryptedBytes
}

func kmsEncrypt(plainText []byte) []byte {

	keyId := os.Getenv("KMS_KEY_ID")
	keySpec := "AES_128"
	dataKeyInput := kms.GenerateDataKeyInput{KeyId: &keyId, KeySpec: &keySpec}

	dataKeyOutput, err := kmsClient.GenerateDataKey(&dataKeyInput)
	if err != nil {
		panic(err)
	}

	p := &payload{
		Key:   dataKeyOutput.CiphertextBlob,
		Nonce: &[nonceLength]byte{},
	}

	p.WrappedKey = wrapKey(dataKeyOutput.Plaintext)

	if _, err = rand.Read(p.Nonce[:]); err != nil {
		panic(err)
	}

	key := &[keyLength]byte{}
	copy(key[:], dataKeyOutput.Plaintext)

	p.Message = secretbox.Seal(p.Message, plainText, p.Nonce, key)

	buf := &bytes.Buffer{}
	if err := gob.NewEncoder(buf).Encode(p); err != nil {
		panic(err)
	}

	return buf.Bytes()
}

func kmsDecrypt(cipherText []byte) []byte {
	var p payload
	gob.NewDecoder(bytes.NewReader(cipherText)).Decode(&p)

	dataKeyOutput1, err := kmsClient.Decrypt(&kms.DecryptInput{
		CiphertextBlob: p.Key,
	})
	if err != nil {
		panic(err)
	}

	key1 := &[keyLength]byte{}
	copy(key1[:], dataKeyOutput1.Plaintext)

	var plaintext []byte
	plaintext, ok := secretbox.Open(plaintext, p.Message, p.Nonce, key1)
	if !ok {
		panic("Failed to open secretbox")
	}

	return plaintext
}

func hsmDecrypt(cipherText []byte) []byte {
	var p payload
	gob.NewDecoder(bytes.NewReader(cipherText)).Decode(&p)

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "priv1"),

		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),

		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),

		pkcs11.NewAttribute(pkcs11.CKA_WRAP_WITH_TRUSTED, false),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false),
	}

	if err := p11Func.FindObjectsInit(session, privateKeyTemplate); err != nil {
		panic(err)
	}

	privKeySlice, _, err := p11Func.FindObjects(session, 1)
	if err != nil {
		panic(err)
	}
	if err = p11Func.FindObjectsFinal(session); err != nil {
		panic(err)
	}

	priKey := privKeySlice[0]

	params := pkcs11.NewOAEPParams(pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, pkcs11.CKZ_DATA_SPECIFIED, nil)
	ret := p11Func.DecryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, params)}, priKey)
	checkResult(ret, "C_DecryptInit")

	unwrappedKey, ret := p11Func.Decrypt(session, p.WrappedKey)
	checkResult(ret, "C_Decrypt")

	key1 := &[keyLength]byte{}
	copy(key1[:], unwrappedKey)

	var plaintext []byte
	plaintext, ok := secretbox.Open(plaintext, p.Message, p.Nonce, key1)
	if !ok {
		panic("Failed to open secretbox")
	}

	return plaintext
}

func main() {

	log.Println("Connecting to SoftHSM")

	lib := "/opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so"
	p11Func = pkcs11.New(lib)

	p11Func.Initialize()
	slot, ret := p11Func.GetSlotList(true)
	checkResult(ret, "GetSlotList")

	session, ret = p11Func.OpenSession(slot[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	checkResult(ret, "OpenSession")

	ret = p11Func.Login(session, pkcs11.CKU_USER, "1234")
	checkResult(ret, "Login")
	log.Println("Connected to HSM")

	log.Println("Generating RSA Key Pair")
	generateRSAKeyPair()

	log.Println("Exporting Public Key to ./hsm_public.pem")
	exportPubKey()

	log.Println("Initializing KMS Client and Session")
	//sess := awssession.Must(awssession.NewSession())

	cfg := aws.Config{
		Endpoint: aws.String("http://localhost:4566"),
		Region:   aws.String("us-west-1"),
	}
	sess := awssession.Must(awssession.NewSession(&cfg))

	kmsClient = kms.New(sess, aws.NewConfig().WithRegion("us-west-1"))
	log.Println("KMS Client Initialized")

	log.Println("Calling KMS Encrypt")
	plainText := []byte("Vishal")
	cipherText := kmsEncrypt(plainText)
	log.Println("KMS Encrypted Value", base64.StdEncoding.EncodeToString(cipherText))

	log.Println("Calling KMS Decrypt")
	kmsDecryptedValue := kmsDecrypt(cipherText)
	log.Println("KMS Decrypted Plaintext: ", string(kmsDecryptedValue))

	log.Println("Calling HSM Decrypt")
	hsmDecrypt(cipherText)
	log.Println("HSM Decrypted Plaintext: ", string(kmsDecryptedValue))

	log.Println("Closing HSM Session")
	p11Func.Logout(session)
	p11Func.CloseSession(session)
	p11Func.Finalize()
	log.Println("Disconnected from HSM")
}
