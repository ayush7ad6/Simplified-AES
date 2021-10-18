# Simplified AES

### _Implementation using Client-Server Communication_

- Enter two alphabets long message and secretkey i.e. 16-bits of data each.

## Client Server Communication

- ### client.py

  - **modules(built-in)**
    - multiprocessing: _sending and receiving message oriented pickles with ease_
    - pickle: _to send and receive objects_
    - hashlib: _to hash message using different hashing algorithms_
  - **modules(created)**
    - rsa _(rsa.py)_: rsa class for encryption, decryption and compute public and private keys
    - encryption _(encryption.py)_: aes variant encryption and key generation
  - **inputs** :
    - message
    - secret key
    - client key parameters
  - **operations**
    - requests and receives server public key from server _(server.py)_
    - encrypts secret key and sends it to the server
    - encrypts plaintext and sends ciphertext to the server
    - sends client public key to the server
    - computes client signature by hasing message and sends it to the server

- ### server.py
  - **modules(built-in)**
    - multiprocessing: _sending and receiving message oriented pickles with ease_
    - pickle: _to send and receive objects_
    - hashlib: _to hash message using different hashing algorithms_
  - **modules(created)**
    - rsa _(rsa.py)_: _rsa class for encryption, decryption and compute public and private keys_
    - decryption _(decryption.py)_: _aes variant decryption and key generation_
  - **inputs** :
    - server key parameters
  - **operations**
    - sends server public key to client _(client.py)_
    - receives encyrpted secret key from client
    - receives encyrpted plaintext(cipher text) from client
    - decrypts ciphertext using aes variant
    - receives client public key for signature verification
    - computes client signature by hasing message and verifies it with the message digest

---

## Modules

- ### func.py
  - isPrime(): returns True if a number is prime False otherwise
  - gcd(): return the greatest common divisor of an integer
  - is_coprime(): return True if two integers are co-prime i.e. their gcd is 1
  - modInverse(): returns the modular inverse of a mod b
  - ConvertToInt(): converts a string to its integer equivalent using each character's ASCII value
  - ConvertToStr(): takes the integer output of ConvertToInt() as an input to compute the string fed in ConvertToInt()
- ### rsa.py
  _Rsa class for encryption, decryption and key generation_
  - **Module _(created)_**
    - func _(func.py)_
  - **Parameters**: Key Generation Paramters (p,q,r)
  - **Variables**:
    - `p`,`q`,`e` (key generation parameters)
    - `n` _(p\*q)_
    - `phi` _(p-1)(q-1)_
    - `prKey` (private Key)
    - `pubKey` (public key)
    - `plaintext` (message to be encrypted)
    - `ciphertext` (encrypted message)
    - `f` (flag for key parameters validation)
  - **Methods**:
    - Constructor: initialises key parameters, validates them and generates key if key parameters valid
    - genKey(): generates public key and private upon validation else assigns `f = 1`
    - validate(): checks the validity of key generation parameters
    - encrypt(): encrypts the `plaintext` with `prkey` generated using `genKey()`. Also, a duplicate function can be used independently without instantiating the class object.
    - decrypt(): decrypts the `ciphertext` with the `pubKey` generated using `genKey()`. Also, a duplicate function can be used independently without instantiating the class object.

---

## S-AES Variant Modules

- ### encryption.py
  - **Modules(built-in)**
    - bitstring: _for bit manipulation_ **(install using `pip install bitstring`)**
    - galois: _for galois field operations_ **(install using `pip install galois`)**
  - **Methods**
    - formString(): create and returns a string from bit array with each block separated with a space
    - formBlocks(): returns a list from a stirng of bit array with each block separated with a space
    - encodeText(): just calls formBlocks()
    - toBits(): takes a string and converts it into bit array string
    - fromBits(): takes an bit array and converts it into string
    - SubNib(): returns a string after substituting nibbles as per simplied aes variant
    - RotNib(): returns a string after rotating rows as per simplied aes variant
    - keyGeneration(): return a dictionary of keys generated from the secret key
    - galoisMultiply(): returns the multiplication result of lookup matrix with intermediate ciphertext computation matrix in the form of a string
    - encryption(): main computation for aes variant encryption using the aforementioned methods
- ### decryption.py
  - **Modules(built-in)**
    - bitstring: _for bit manipulation_ **(install using `pip install bitstring`)**
    - galois: _for galois field operations_ **(install using `pip install galois`)**
  - **Methods**
    - formString(): create and returns a string from bit array with each block separated with a space
    - formBlocks(): returns a list from a stirng of bit array with each block separated with a space
    - encodeText(): just calls formBlocks()
    - toBits(): takes a string and converts it into bit array string
    - fromBits(): takes an bit array and converts it into string
    - SubNib(): returns a string after substituting nibbles as per simplied aes variant
    - dSubNib(): works same as SubNib() but for decryption using decrypt s-box
    - RotNib(): returns a string after rotating rows as per simplied aes variant
    - keyGeneration(): return a dictionary of keys generated from the secret key
    - galoisMultiply(): returns the multiplication result of lookup matrix with intermediate ciphertext computation matrix in the form of a string
    - decryption(): main computation for aes variant decryption using the aforementioned methods

---

:cyclone: :cyclone: :cyclone:
