# hybrid_crypto
The repo/script demonstrates a sample encryption technique where KMS data key is encrypted using HSM generated public key for break glass privileges. In event where KMS is not available the encrypted output can be decrypted using HSM. 

### Steps
- Connect to SoftHSM
- Generate RSA 2048 key pair
- Export RSA public key
- Call KMS GenerateDataKey, which provides encrypted and plaintext data keys
- Generate output which includes encrypted input value using KMS and public key encrypted KMS plaintext key
- Decrypt value using KMS and HSM

### Install Localstack
Follow directions here to install localstack. This provides a local AWS development environment
https://docs.localstack.cloud/getting-started/installation/

### Install SoftHSM
`brew install softhsm`
Depending on your install, the homebrew will install SoftHSM at `/opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so` 

### Verify Installation
`softhsm2-util`



After SoftHSM has been been, the following command can be used to initialize the token required by the unit tests:
```
softhsm2-util --init-token --slot 0 --label "ForKMS" --so-pin 1234 --pin 1234
```


If using localstack for AWS, then generate KMS key
```
awslocal kms create-key

{
    "KeyMetadata": {
        "AWSAccountId": "000000000000",
        "KeyId": "90cdf930-0e4d-44a8-b802-30150ec31d11",
        "Arn": "arn:aws:kms:us-west-1:000000000000:key/90cdf930-0e4d-44a8-b802-30150ec31d11",
        "CreationDate": "2023-04-20T10:07:40.067652-07:00",
        "Enabled": true,
        "Description": "",
        "KeyUsage": "ENCRYPT_DECRYPT",
        "KeyState": "Enabled",
        "Origin": "AWS_KMS",
        "KeyManager": "CUSTOMER",
        "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
        "KeySpec": "SYMMETRIC_DEFAULT",
        "EncryptionAlgorithms": [
            "SYMMETRIC_DEFAULT"
        ],
        "MultiRegion": false
    }
}
```
Export the key ID to environment
```
export KMS_KEY_ID="90cdf930-0e4d-44a8-b802-30150ec31d11"
```



### Execute the script

`go run cmd/crypto/main.go`

```
2022/12/21 16:23:03 Connecting to SoftHSM
2022/12/21 16:23:03 Connected to HSM
2022/12/21 16:23:03 Generating RSA Key Pair
2022/12/21 16:23:03 RSA-2048 keypair generated.
2022/12/21 16:23:03    - Private Key : 3
2022/12/21 16:23:03    - Public Key  : 2
2022/12/21 16:23:03 Exporting Public Key to ./hsm_public.pem
2022/12/21 16:23:03   Public Key: 
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAxt4kPXJHha/WTc/ashVwGNwe2jJf01o/Sldv7gGnTYZErVkbXNRR
dk68SjeVy2X2cxY5aO7JRtLV9b/+ykzrPSPtRF+qDvvaZi8ZCzswyOwr2mOEhPvs
+2R+9rapQWMeF+RsPiBnlmIOUQFGM1OdM7EXGPzfDLiLWM0kCvyf0dFCqbtUhPXn
PI4oyO6EK1ur/LzjQuBl0lDdQa1rcVw+uu5AhdbgQhhiTl1wYtioJ1Uzqk0MR/fv
xC/2tTDD5MWjicLXUKGEzN4bgywBHH7ZUgzlO6K74tjqVCCQguHMW4NtMasYOaD7
ELg6eEDFEMnlqfZigR84/rsMS/qvhlRx1QIDAQAB
-----END RSA PUBLIC KEY-----

2022/12/21 16:23:03 Initializing KMS Client and Session
2022/12/21 16:23:03 KMS Client Initialized
2022/12/21 16:23:03 Calling KMS Encrypt
2022/12/21 16:23:03 KMS Encrypted Value Q/+BAwEBB3BheWxvYWQB/4IAAQQBA0tleQEKAAEKV3JhcHBlZEtleQEKAAEFTm9uY2UB/4QAAQdNZXNzYWdlAQoAAAAZ/4MBAQEJWzI0XXVpbnQ4Af+EAAEGATAAAP4B7/+CAf+oAQIDAHhSjGuzHdxoPl0YwgMVyrQI9WozPUAS6o8y5CKtj4uMrgHyEIgbsqrNbK394C/5s27MAAAAbjBsBgkqhkiG9w0BBwagXzBdAgEAMFgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMc2DX9phCPOU1nqemAgEQgCueOlD536Jk3fhjzS4sFGqxu7/dAZAIBtXxYf99zbSWOPddMbqYEaTPG4ZDAf4BACHElkD45MaGAZhSEqDnyOE1nwfHfWSW8UYgLyKf+MBKV2wulDc0iAzIpcBWGH3eqGoPCtg4isd87RPcaURn6wGJZlYqJiL/fOeHaXqZqA4ref7lC8EhX2OyhVxXFt+JM3PCVOwckm848844gi4R1Enh9pWiFXiPjS4RhwqXs/0JBX6AH/dEJ9xujljnydHLXFRtEl7Iq2Vaziz9bXWrL4eM83Pm4B3wd5I6PohSnsDSrk10NrIHZiUdm44oo4fgtupPiEZ5J+AgT7B0s+XLO8VvfBOFb5KClEicxekKyAFVSWxa5DFJ5Q8zS+9tdi9jKLE5gBX45Q7PJ7xp85lZDI8BGClz/+1h/4oq/64NQCf/327/4P/rAgj/rP+uCv/f/+prIP+XARaS8bSzOHrcPPMqQ7sWbyyJa4E9fhCBAA==
2022/12/21 16:23:03 Calling KMS Decrypt
2022/12/21 16:23:03 KMS Decrypted Plaintext:  Vishal
2022/12/21 16:23:03 Calling HSM Decrypt
2022/12/21 16:23:03 HSM Decrypted Plaintext:  Vishal
2022/12/21 16:23:03 Closing HSM Session
2022/12/21 16:23:03 Disconnected from HSM
```
