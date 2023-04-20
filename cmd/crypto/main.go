package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"sync"
	"unsafe"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/miekg/pkcs11"
	"golang.org/x/crypto/nacl/secretbox"

	awssession "github.com/aws/aws-sdk-go/aws/session"
)

const (
	keyLength   = 32
	nonceLength = 24
	rsaModBits  = 2048
)

var (
	kmsClient *kms.KMS
	p11Func   = pkcs11.New("")
	session   pkcs11.SessionHandle

	pubKey     *rsa.PublicKey
	pubKeyOnce sync.Once

	publicTemplate = keyTemplate{
		token:   true,
		private: true,
		encrypt: true,
		verify:  true,
		wrap:    true,
		label:   "pub1",
	}

	privateTemplate = keyTemplate{
		token:       true,
		private:     true,
		decrypt:     true,
		sign:        true,
		unwrap:      true,
		extractable: false,
		modifiable:  false,
		sensitive:   true,
		label:       "priv1",
	}

	payloadPool = sync.Pool{
		New: func() interface{} {
			return &payload{
				Nonce: &[nonceLength]byte{},
			}
		},
	}
)

type keyTemplate struct {
	token       bool
	private     bool
	encrypt     bool
	verify      bool
	wrap        bool
	decrypt     bool
	sign        bool
	unwrap      bool
	extractable bool
	modifiable  bool
	sensitive   bool
	label       string
}

type payload struct {
	Key        []byte
	WrappedKey []byte
	Nonce      *[nonceLength]byte
	Message    []byte
}

func checkError(ret error, message string) {
	if ret != nil {
		log.Fatalf("Problem occured during %s : %s\n", message, ret)
		p11Func.Finalize()
		os.Exit(1)
	}
}

func generateRSAKeyPair() (pkcs11.ObjectHandle, pkcs11.ObjectHandle) {

	rsaExponent := []byte{0x01, 0x00, 0x00, 0x00, 0x01}

	pubAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, publicTemplate.token),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, publicTemplate.private),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, publicTemplate.encrypt),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, publicTemplate.verify),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, publicTemplate.wrap),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, rsaModBits),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, rsaExponent),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, publicTemplate.label),
	}

	priAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, privateTemplate.token),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, privateTemplate.private),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, privateTemplate.decrypt),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, privateTemplate.sign),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, privateTemplate.unwrap),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, privateTemplate.extractable),
		pkcs11.NewAttribute(pkcs11.CKA_MODIFIABLE, privateTemplate.modifiable),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, privateTemplate.sensitive),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, privateTemplate.label),
	}

	pubKey, priKey, err := p11Func.GenerateKeyPair(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}, pubAttrs, priAttrs)

	checkError(err, "p11Func.GenerateKeyPair")
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
		checkError(err, "FindObjectsInit")
	}

	pubKeySlice, _, err := p11Func.FindObjects(session, 1)
	if err != nil {
		checkError(err, "FindObjects")
	}
	if err = p11Func.FindObjectsFinal(session); err != nil {
		checkError(err, "FindObjectsFinal")
	}

	pubKey := pubKeySlice[0]
	pr, err := p11Func.GetAttributeValue(session, pubKey, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	})
	if err != nil {
		checkError(err, "GetAttributeValue")
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

	pubKeyPemEncode := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(rsaPub),
	})

	err = ioutil.WriteFile("hsm_public.pem", pubKeyPemEncode, 0644)
	checkError(err, "ioutil.WriteFile")

}

func loadPublicKey() {
	pub, err := ioutil.ReadFile("hsm_public.pem")
	checkError(err, "ReadPublicFileFromDisk")

	pubPem, _ := pem.Decode(pub)
	if pubPem == nil || pubPem.Bytes == nil {
		checkError(errors.New("empty Pub Key"), "EmptyOrNullKey")
	}

	var parsedKey interface{}
	var ok bool

	parsedKey, err = x509.ParsePKCS1PublicKey(pubPem.Bytes)
	checkError(err, "ParsePKCS1PublicKey")

	if pubKey, ok = parsedKey.(*rsa.PublicKey); !ok {
		checkError(err, "parsedKey")
	}
}

func wrapKey(key []byte) []byte {
	pubKeyOnce.Do(loadPublicKey)

	encryptedBytes, err := rsa.EncryptPKCS1v15(
		rand.Reader,
		pubKey,
		key,
	)
	if err != nil {
		checkError(err, "EncryptPKCS1v15")
	}

	return encryptedBytes
}

func kmsEncrypt(plainText []byte) []byte {
	keyId := os.Getenv("KMS_KEY_ID")
	keySpec := "AES_128"
	dataKeyInput := kms.GenerateDataKeyInput{KeyId: &keyId, KeySpec: &keySpec}

	dataKeyOutput, err := kmsClient.GenerateDataKey(&dataKeyInput)
	if err != nil {
		checkError(err, "GenerateDataKey")
	}

	p := payloadPool.Get().(*payload)
	defer payloadPool.Put(p)

	p.Key = dataKeyOutput.CiphertextBlob
	p.WrappedKey = wrapKey(dataKeyOutput.Plaintext)

	if _, err = rand.Read(p.Nonce[:]); err != nil {
		checkError(err, "rand.Read")
	}

	key := &[keyLength]byte{}
	copy(key[:], dataKeyOutput.Plaintext)

	p.Message = secretbox.Seal(p.Message[:0], plainText, p.Nonce, key)

	// Using a pre-allocated buffer of size 256 to encode the payload struct. Adjust this buffer size depending on use case
	buf := bytes.NewBuffer(make([]byte, 0, 256))
	if err := gob.NewEncoder(buf).Encode(p); err != nil {
		checkError(err, "gob.NewEncoder")
	}

	return buf.Bytes()
}

func kmsDecrypt(cipherText []byte) []byte {
	var p payload
	gob.NewDecoder(bytes.NewReader(cipherText)).Decode(&p)

	dataKeyOutput, err := kmsClient.Decrypt(&kms.DecryptInput{
		CiphertextBlob: p.Key,
	})
	checkError(err, "kmsClient.Decrypt")

	key := &[keyLength]byte{}
	copy(key[:], dataKeyOutput.Plaintext)

	plaintext, ok := secretbox.Open(nil, p.Message, p.Nonce, key)
	if !ok {
		err = errors.New("failed to decrypt message")
	}
	checkError(err, "secretbox.Open")

	return plaintext
}

func hsmDecrypt(cipherText []byte) []byte {
	var p payload
	gob.NewDecoder(bytes.NewReader(cipherText)).Decode(&p)

	priAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, privateTemplate.token),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, privateTemplate.private),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, privateTemplate.sensitive),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, privateTemplate.label),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, privateTemplate.sign),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, privateTemplate.decrypt),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, privateTemplate.extractable),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP_WITH_TRUSTED, false),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false),
	}

	if err := p11Func.FindObjectsInit(session, priAttrs); err != nil {
		checkError(err, "FindObjectsInit")
	}

	privKeySlice, _, err := p11Func.FindObjects(session, 1)
	if err != nil {
		checkError(err, "FindObjects")
	}
	if err = p11Func.FindObjectsFinal(session); err != nil {
		checkError(err, "FindObjectsFinal")
	}

	priKey := privKeySlice[0]

	params := pkcs11.NewOAEPParams(pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, pkcs11.CKZ_DATA_SPECIFIED, nil)
	ret := p11Func.DecryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, params)}, priKey)

	checkError(ret, "C_DecryptInit")

	unwrappedKey, ret := p11Func.Decrypt(session, p.WrappedKey)
	checkError(ret, "C_Decrypt")

	key1 := (*[keyLength]byte)(unsafe.Pointer(&(unwrappedKey)[0]))

	var plaintext []byte
	plaintext, ok := secretbox.Open(plaintext, p.Message, p.Nonce, key1)
	if !ok {
		checkError(err, "secretbox.Open")
	}

	return plaintext
}

func main() {

	log.Println("Connecting to SoftHSM")

	lib := "/opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so"
	p11Func = pkcs11.New(lib)

	p11Func.Initialize()
	slot, ret := p11Func.GetSlotList(true)
	checkError(ret, "GetSlotList")

	session, ret = p11Func.OpenSession(slot[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	checkError(ret, "OpenSession")

	ret = p11Func.Login(session, pkcs11.CKU_USER, "1234")
	checkError(ret, "Login")
	log.Println("Connected to HSM")

	log.Println("Generating RSA Key Pair")
	generateRSAKeyPair()

	log.Println("Exporting Public Key to ./hsm_public.pem")
	exportPubKey()

	log.Println("Initializing KMS Client and Session")
	// To AWS instead of localstack, change the sess to below line
	//sess := awssession.Must(awssession.NewSession())
	cfg := aws.Config{
		Endpoint: aws.String("http://localhost:4566"),
		Region:   aws.String("us-west-1"),
	}
	sess := awssession.Must(awssession.NewSession(&cfg))

	kmsClient = kms.New(sess, aws.NewConfig().WithRegion("us-west-1"))
	log.Println("KMS Client Initialized")

	log.Println("Calling KMS Encrypt")
	plainText := []byte("344543323456643322")
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
