from Cryptodome.Cipher import AES
import bcrypt
import getpass

OUT_FILE = "token.dat"

print("Введіть Ваш ключ доступу з data.gov.ua: ")
token = input() 
password = getpass.getpass("Створіть пароль, аби зашифрувати файл: ")
key = bcrypt.kdf(password = password.encode(), salt = b"salt", desired_key_bytes = 32, rounds = 100)
cipher = AES.new(key, AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(token.encode())
file_out = open(OUT_FILE, "wb")
[file_out.write(x) for x in (cipher.nonce, tag, ciphertext)]
