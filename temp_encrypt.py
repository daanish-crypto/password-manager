#this imports the cryptography package
from cryptography.fernet import Fernet
'''
#this generates a key and opens a file 'key.key' and writes the key there
key = Fernet.generate_key()
with open('key.key','wb') as file:
    file.write(key)
'''
#this just opens your 'key.key' and assings the key stored there as 'key'
with open('key.key','rb') as file:
    key = file.read()

#this opens your json and reads its data into a new variable called 'data'
with open('passwords.txt','rb') as f:
    data = f.read()

fernet = Fernet(key)
decrypted = fernet.decrypt(data)

print(decrypted)

with open("unencrypted_password.json", "wb") as upass:
    upass.write(decrypted)
'''
#this encrypts the data read from your json and stores it in 'encrypted'
fernet = Fernet(key)
encrypted = fernet.encrypt(data)

#this writes your new, encrypted data into a new JSON file
with open('passwords.json','wb') as f:
    f.write(encrypted)

'''