# StringCrypt
## Simple (long) String encryption and signing for Android/Java using public keys

Allows to encrypt long Strings with RSA public key algorithm. RSA cipher is limited to a specific
length in JAVA/Android. The String is encryped by symmetric DESede algorithm and only the symmetric
session key is encrypted by RSA. The encrypted message and the symmetric key are packaged and can
be exported as base64 encoded string or byte array.

The recipient can then decrypt the symmetric key with his private key and use the symmetric key to
decrypt the message.

Signing is using a sha1 footprint of the message and signs it with the private key. The receiving
party can use the senders public key to verify the validity of the signature.

## Usage
### Encrypting and decrypting Strings
```java
// Init object
StringCrypt crypt = new StringCrypt();

// generate key pair for demonstration (or each party reads either from storage)
KeyPair kp = crypt.createKeyPair();
Key privateKey = kp.getPrivate();
Key publicKey = kp.getPublic();

// encrypt String message to CryptPackage and/or encode package as String
CryptPackage cryptPackage = crypt.encrypt(message, publicKey);
String packageString = cryptPackage.toString();

// ~~~ Do something with packageString, eg transmit over network

// Receiving party decrypt package from String
CryptPackage newPackage = new CryptPackage(packageString);
String decryptedString = crypt.decrypt(newPackage, privateKey);
```

### Signing Strings
```java
// Init object
StringSign sign = new StringSign();

// generate key pair for demonstration (or each party reads either from storage)
KeyPair kp = crypt.createKeyPair();
Key privateKey = kp.getPrivate();
Key publicKey = kp.getPublic();

// sign String with private key and return signature as String
String signature = sign.sign(message, privateKey);

// ~~~ Do something with signature string, eg transmit over network

// Receiving party can verify String with signature and public key of sender
Boolean verified = sign.verify(message, signature, publicKey);
```

## Credits
Some elements are inspired from https://github.com/william-ferguson-au/asymmetric-crypto but I
chose to simplify it even down to only two classes
