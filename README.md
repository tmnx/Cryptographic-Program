# Cryptographic-Program
A program to safely encrypt and decrypt files.

## Algorithmns:
- SHA-3 derived function KMACXOF256
- ECDHIES encryption & Schnorr signatures

### Hash from a selected file:
1. Press key ‘1’ [ENTER]
2. After a file choose window popup, choose a test file in the ‘testFile’ folder (or create one)
& choose ‘Open’

<img width="596" alt="Screen Shot 2020-06-16 at 9 34 05 PM" src="https://user-images.githubusercontent.com/51972672/84855502-1f0f7880-b019-11ea-836c-cb93e67654f9.png">

3. The hash result is printed on the console (might need to scroll up to see)

<img width="849" alt="Screen Shot 2020-06-16 at 9 39 16 PM" src="https://user-images.githubusercontent.com/51972672/84855799-dc01d500-b019-11ea-9e0a-6623c05f7e27.png">

### Hash from user input:
1. Press ‘2’ [ENTER]
2. Type in a message that is to be hashed [ENTER]
3. The hash result is printed on the console (might need to scroll up to see)

<img width="855" alt="Screen Shot 2020-06-16 at 9 40 16 PM" src="https://user-images.githubusercontent.com/51972672/84855840-fc319400-b019-11ea-833c-2ea85da8b9bd.png">

### Encrypt a file symmetrically under a given passphrase:
1. Press ‘3’ [ENTER]
2. Select a file to encrypt
3. Enter a passphrase [ENTER]
4. Encrypted result is printed to the console
5. The file is now securely encrypted (user cannot see the file content until it is decrypted
with the correct passphrase)

<img width="860" alt="Screen Shot 2020-06-16 at 9 41 15 PM" src="https://user-images.githubusercontent.com/51972672/84855896-208d7080-b01a-11ea-939e-7fcb6e265997.png">

If the user open the encrypted file, this is the result:
<img width="839" alt="Screen Shot 2020-06-16 at 9 42 26 PM" src="https://user-images.githubusercontent.com/51972672/84855975-4a469780-b01a-11ea-8e63-b7718526b58f.png">

### Decrypt a file symmetrically under a given passphrase:
1. Press ‘4’ [ENTER]
2. Select an encrypted file to decrypt
3. Enter the correct passphrase for the encrypted file [ENTER]
4. The decrypted content is in the file name ‘output.txt’ in the local project folder

### Compute an authentication tag of a given file under a given passphrase:
1. Press ‘5’ [ENTER]
2. Select a file & click ‘Open’
3. Enter a passphrase [ENTER]
4. The authentication tag is printed to the console

<img width="846" alt="Screen Shot 2020-06-16 at 9 43 37 PM" src="https://user-images.githubusercontent.com/51972672/84856050-7bbf6300-b01a-11ea-941f-5205413a0a86.png">

### Generate an elliptic key pair from a given passphrase and write the public key to a file:
1. Press ‘6’ [ENTER]
2. Enter a passphrase [ENTER]
3. The public key is saved to the file name GENERATED_PUBLIC_KEY in the local
source file

<img width="608" alt="Screen Shot 2020-06-16 at 9 44 37 PM" src="https://user-images.githubusercontent.com/51972672/84856137-ad382e80-b01a-11ea-84f6-65379aedf98f.png">

### Encrypt a data file under a given elliptic public key file:
1. Press ‘7’ [ENTER]
2. Choose a data file & click ‘Open’
3. Choose an elliptic public key file & click ‘Open’
<img width="500" alt="Screen Shot 2020-06-16 at 9 46 01 PM" src="https://user-images.githubusercontent.com/51972672/84856186-ce008400-b01a-11ea-86ed-8ef011a93327.png">

4. The Encrypted data under the public key file is saved as ENCRYPTED_CRYPTOGRAM
in the local source file.

### Decrypt a given elliptic-encrypted file from a given password:
1. Press ‘8’ [ENTER]
2. Select an elliptic encrypted file & click ‘Open’
<img width="575" alt="Screen Shot 2020-06-16 at 9 47 10 PM" src="https://user-images.githubusercontent.com/51972672/84856230-f2f4f700-b01a-11ea-85d2-6a1510e6ea38.png">

3. Enter the correct passphrase [ENTER]
4. The decrypted content is saved in the file ‘output_elliptic_file.txt’

#### Emcrypted file content:
<img width="519" alt="Screen Shot 2020-06-16 at 9 48 02 PM" src="https://user-images.githubusercontent.com/51972672/84856264-115af280-b01b-11ea-82fd-c048757441da.png">

### Decrypted file content:
<img width="632" alt="Screen Shot 2020-06-16 at 9 48 49 PM" src="https://user-images.githubusercontent.com/51972672/84856300-2df72a80-b01b-11ea-9507-467c0e3179b6.png">
