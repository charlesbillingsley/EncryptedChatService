"""
    Created by Charles Billingsley

    Code heavily copied from tutorial at:
    https://www.blog.pythonlibrary.org/2016/05/18/python-3-an-intro-to-encryption/

    Encryption module available at:
    http://pycryptodome.readthedocs.io/en/latest/
"""

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP


def generate_keys():
    """
        Generate Key
    """
    #  Quick way to generate a new key
    key = RSA.generate(1024)

    """
        Encrypt My Key
    """
    private_key = key.exportKey(pkcs=8, protection="scryptAndAES128-CBC")

    # Show the real content of the private part to console
    # Be careful with this!
    print('\n======================= PRIVATE KEY ============================')
    print(private_key)
    print('================================================================')

    """
        Public Key Creation
    """
    # Get the public part
    public_key = key.publickey().exportKey()

    # Show the real content of the public key to console
    # This is the one to share!
    print('\n======================= PUBLIC KEY =============================')
    print(public_key)
    print('================================================================')

    """
        Export Keys to files
    """
    # Save both keys into some file for future usage if needed
    with open("my_rsa_private.pem", "wb") as pvt_file:
        pvt_file.write(private_key)

    with open("my_rsa_public.pem", "wb") as pub_file:
        pub_file.write(public_key)


def encrypt():
    """
    Encrypts the test file
    """

    # open up a file to write to
    with open("encrypted_data.bin", 'wb') as out_file:

        # import our public key into a variable
        recipient_key = RSA.import_key(open('my_rsa_public.pem').read())

        # create a 16-byte session key
        session_key = get_random_bytes(16)

        # Optimal asymmetric encryption padding allows us to write a data
        # of an arbitrary length to the file
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        out_file.write(cipher_rsa.encrypt(session_key))

        # create our AES cipher
        cipher_aes = AES.new(session_key, AES.MODE_EAX)

        # some data to encrypt
        data = b'This is some test data to encrypt'

        # Encrypt the data. This returns the encrypted text and MAC
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)

        # Write the nonce, MAC (tag), and encrypted text to the file
        # a nonce is an arbitrary number that is only used for
        # cryptographic communication. They are usually random or
        # pseudo-random numbers. For AES, it must be at least
        # 16 bytes in length.
        out_file.write(cipher_aes.nonce)
        out_file.write(tag)
        out_file.write(ciphertext)

        print('\n======================= '
              'DATA TO ENCRYPT ========================')
        print(data)
        print(
            '================================================================')


def decrypt():
    """
    Decrypts the test file
    """
    # opening our encrypted file for reading in binary mode.
    with open('encrypted_data.bin', 'rb') as file:

        # Import our private key
        private_key = RSA.import_key(open('my_rsa_private.pem').read())

        # Read in our file. You will note that we read in the private
        # key first, then the next 16 bytes for the nonce, which is followed
        # by the next 16 bytes which is the tag and finally the rest of the
        # file, which is our data.
        encrypted_session_key, nonce, tag, ciphertext = \
            [file.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]

        # Decrypt our session key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(encrypted_session_key)

        # Recreate our AES key and decrypt the data
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    print('\n======================= DECRYPTED DATA =========================')
    print(data)
    print('================================================================')


if __name__ == "__main__":
    '''
        Run the Test
    '''
    generate_keys()
    encrypt()
    decrypt()

