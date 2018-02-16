import pgpy

print("Please input text to encrypt")
text_to_encrypt = input()


# this creates a standard message from text
# it will also be compressed, by default with ZIP DEFLATE, unless otherwise specified
text_message = pgpy.PGPMessage.new(text_to_encrypt)

print('Plain text message')
# plain text of the PGP message
print(text_message.message)


print("Please input pass phrase to encrypt the message")
pass_phrase = 'test'

# the .encrypt method returns a new PGPMessage object which contains the encrypted
# contents of the old message
enc_message = text_message.encrypt(pass_phrase)

print('Encrypted message')
# plain text of the encrypted PGP message
print(str(enc_message))

# message.is_encrypted is False
# enc_message.is_encrypted is True
# a message that was encrypted using a passphrase can also be decrypted using
# that same passphrase
dec_message = enc_message.decrypt(pass_phrase)

print('Decrypted message')
# plain text of the decrypted PGP message
print(dec_message.message)

t_msg = 'suneel'

try:
    new_message = pgpy.PGPMessage.from_blob(str(t_msg))

    # message.is_encrypted is False
    # enc_message.is_encrypted is True
    # a message that was encrypted using a passphrase can also be decrypted using
    # that same passphrase
    dec_message = new_message.decrypt(pass_phrase)

    print('Decrypted message 2')
    # plain text of the decrypted PGP message
    print(dec_message.message)
except ValueError:
    print('Not a valid PGP message for decryption')
    print(t_msg)

