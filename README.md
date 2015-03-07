# StringCrypt
## Simple String encryption for Android

Allows to encrypt long Strings with RSA public key algorithm. RSA cipher is limited to a specific
length in JAVA/Android. The String is encryped by symmetric DESede algorithm and only the symmetric
session key is encrypted by RSA. The encrypted message and the symmetric key are packaged and can
be exported as base64 encoded string or byte array.

## Usage
```java
 StringCrypt crypt = new StringCrypt();

 KeyPair kp = crypt.createKeyPair();
 Key privateKey = kp.getPrivate();
 Key publicKey = kp.getPublic();

 CryptPackage cryptPackage = crypt.encrypt(message, publicKey);
 String packageString = cryptPackage.toString();
 // Do something with packageString, eg network transmit
 CryptPackage newPackage = new CryptPackage(packageString);
 String decryptedString = crypt.decrypt(newPackage, privateKey);
```

## Credits
Some elements are inspired from https://github.com/william-ferguson-au/asymmetric-crypto but I
chose to simplify it even down to only two classes
