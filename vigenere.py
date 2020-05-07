from Crypto.PublicKey import RSA #https://pycryptodome.readthedocs.io/en/latest/src/public_key/public_key.html
from Crypto.Cipher import PKCS1_OAEP #https://pycryptodome.readthedocs.io/en/latest/src/cipher/cipher.html
import time #https://docs.python.org/3/library/time.html
import binascii

class Cipher(object):
    def format_str(self, text):
        return text.replace(' ', '').upper()
 
    def shift_alphabet(self, alphabet, shift):
        
        return alphabet[shift:] + alphabet[:shift] #Retorna alphabet com deslocamento de valor shift
 
class Vigenere(Cipher):
    def __init__(self):
        self.plain = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
 
    def repeat_password(self, password, text):

        if len(password) < len(text):
            new_pass = password * int((len(text)/len(password)))
            if len(new_pass):
                new_pass += password[:len(new_pass)]
            return new_pass.upper()
        return password.upper()
 
    def encrypt(self, plaintext, password, decrypt=False):

        password = self.repeat_password(password, plaintext)
        plaintext = self.format_str(plaintext)
        textout = ''
        for idx, char in enumerate(plaintext.upper()):
            idx_key = self.plain.find(password[idx]) #indice da letra da cifra
            c_alphabet = self.shift_alphabet(self.plain, idx_key) # gera alfabeto cifrado
 
            if decrypt:
                idx_p = c_alphabet.find(char)
                textout += self.plain[idx_p]
            else:
                idx_p = self.plain.find(char)
                textout += c_alphabet[idx_p]
 
        return textout

    def decrypt(self, ciphertext, password):
        
        return self.encrypt(ciphertext, password, True)


class Cod_RSA():

    def __init__(self):
        self.keyPair = RSA.generate(3072)

    def gerarPublicKey(self):
        pubKey = self.keyPair.publickey()
        pubKeyPEM = pubKey.exportKey()
        chave_publica = pubKeyPEM.decode('ascii')
        return pubKey

    def gerarPrivadeKey(self):
        privKeyPEM = self.keyPair.exportKey()
        chave_privada = privKeyPEM.decode('ascii')
        return privKeyPEM

    def encript_RSA(self, msg, pubKey):
        encryptor = PKCS1_OAEP.new(pubKey)
        encrypted = encryptor.encrypt(msg)
        return encrypted
        

    def decript_RSA(self, encrypted, privkey):
        decryptor = PKCS1_OAEP.new(self.keyPair)
        decrypted = decryptor.decrypt(encrypted)
        return(decrypted)


#-------------------------------------------------------------------------------------------------------------------------
print('--------------------------------------------------------------------------')
texto = input('Texto a ser encriptado: ')
senha = input('Chave: ')
print('--------------------------------------------------------------------------')

inicio = time.time()
cifra = Vigenere()
rsa = Cod_RSA()
texto_cifrado = cifra.encrypt(texto, senha)
chavesPublic = rsa.gerarPublicKey()
chavesPrivat = rsa.gerarPrivadeKey()
texto_encript_RSA = rsa.encript_RSA(texto_cifrado.encode(), chavesPublic)
texto_decoded_RSA = rsa.decript_RSA(texto_encript_RSA, chavesPrivat)
texto_original = cifra.decrypt(texto_decoded_RSA.decode(), senha)
fim = time.time()

print()
print('Texto encriptado em Vigenere: {0}'.format(texto_cifrado))
print('--------------------------------------------------------------------------')
print("Texto encriptado em RSA: ", binascii.hexlify(texto_encript_RSA).decode())
print('--------------------------------------------------------------------------')
print('Texto decriptado em RSA: ' + texto_decoded_RSA.decode())
print('--------------------------------------------------------------------------')
print('Texto decriptado em Vigenere: ' + texto_original.lower())
print('--------------------------------------------------------------------------')
print('Tempo de Duração: ' + str(fim - inicio))
print('--------------------------------------------------------------------------')