'''
MIT License

Copyright (c) 2024 Arijit Kumar Das <arijitkdgit.official@gmail.com> and Team ARTISYN

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''

## Important formulae:
#   * base64 encoded length = 4/3 * length of encrypted data
#                           = 4/3 * (length of nonce + length of data + length of auth tag)
#     For a 12 byte nonce and an auth tag of 16 bytes used in AESGCM,
#     base64 encoded length = 4/3 * (length of data + 28)           //[MOST IMPORTANT]


import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64

SUCCESS = 0
FAILURE = 1

def normalizePath (filepath : str):
    filepath = filepath.strip()
    filesep = '/'
    if (os.name == "nt"):
        filesep = '\\'
        if (filepath.find('/') != -1):
            filepath = filepath.replace('/', filesep)
    else:
        if (filepath.find('\\') != -1):
            filepath = filepath.replace('\\', filesep)
    filepath_list = filepath.split(filesep)
    filepath = ""
    for i in range(len(filepath_list)):
        filepath_list[i] = filepath_list[i].strip()
        filepath += (filepath_list[i]+filesep)
    while (filepath.endswith(filesep)):
        filepath = filepath[:-1]
    if (filepath == ""):
        filepath = filesep
    return filepath


def getActualName (filepath : str):
    filesep = '\\' if os.name == "nt" else '/'
    return normalizePath(filepath).split(filesep)[-1]


def encryptFile (filepath : str, key : bytes, guid : str, name_encryption = True):
    filesep = '\\' if os.name == "nt" else '/'
    filepath = normalizePath(filepath)
    with open(filepath, "rb") as file:
        filedata = file.read()
    filedata_nonce = secrets.token_bytes(12)
    filedata_cipher = filedata_nonce + AESGCM(key).encrypt(filedata_nonce, filedata, guid.encode("utf-8"))
    with open(filepath, "wb") as file:
        file.write(filedata_cipher)
    if (name_encryption):
        filename = getActualName(filepath).encode("utf-8")
        filename_nonce = secrets.token_bytes(12)
        filename_cipher = filename_nonce + AESGCM(key).encrypt(filename_nonce, filename, guid.encode("utf-8"))
        base64_encoded_filename_cipher = base64.urlsafe_b64encode(filename_cipher).decode("utf-8")
        encrypted_newfilepath = base64_encoded_filename_cipher
        if (filepath.find(filesep) != -1):
            encrypted_newfilepath = filepath[:(filepath.rindex(filesep)+1)]+base64_encoded_filename_cipher
        os.rename(filepath, encrypted_newfilepath)
        return encrypted_newfilepath
    return SUCCESS


def decryptFile (filepath : str, key : bytes, guid : str, name_decryption = True):
    filesep = '\\' if os.name == "nt" else '/'
    filepath = normalizePath(filepath)
    with open(filepath, "rb") as file:
        filedata_cipher = file.read()
    filedata = AESGCM(key).decrypt(filedata_cipher[:12], filedata_cipher[12:], guid.encode("utf-8"))
    with open(filepath, "wb") as file:
        file.write(filedata)
    if (name_decryption):
        base64_encoded_filename_cipher = getActualName(filepath)
        filename_cipher = base64.urlsafe_b64decode(base64_encoded_filename_cipher)
        filename =  AESGCM(key).decrypt(filename_cipher[:12], filename_cipher[12:], guid.encode("utf-8")).decode("utf-8")
        decrypted_newfilepath = filename
        if (filepath.find(filesep) != -1):
            decrypted_newfilepath = filepath[:(filepath.rindex(filesep)+1)]+filename
        os.rename(filepath, decrypted_newfilepath)
        return decrypted_newfilepath
    return SUCCESS


def encryptDirName (dirpath : str, key : bytes, guid : str):
    filesep = '\\' if os.name == "nt" else '/'
    dirname = getActualName(dirpath).encode("utf-8")
    dirname_nonce = secrets.token_bytes(12)
    dirname_cipher = dirname_nonce + AESGCM(key).encrypt(dirname_nonce, dirname, guid.encode("utf-8"))
    base64_encoded_dirname_cipher = base64.urlsafe_b64encode(dirname_cipher).decode("utf-8")
    encrypted_newdirpath = base64_encoded_dirname_cipher
    if (dirpath.find(filesep) != -1):
        encrypted_newdirpath = dirpath[:(dirpath.rindex(filesep)+1)]+base64_encoded_dirname_cipher
    os.rename(dirpath, encrypted_newdirpath)
    return encrypted_newdirpath


def decryptDirName (dirpath : str, key : bytes, guid : str):
    filesep = '\\' if os.name == "nt" else '/'
    base64_encoded_dirname_cipher = getActualName(dirpath)
    dirname_cipher = base64.urlsafe_b64decode(base64_encoded_dirname_cipher)
    dirname =  AESGCM(key).decrypt(dirname_cipher[:12], dirname_cipher[12:], guid.encode("utf-8")).decode("utf-8")
    decrypted_newdirpath = dirname
    if (dirpath.find(filesep) != -1):
        decrypted_newdirpath = dirpath[:(dirpath.rindex(filesep)+1)]+dirname
    os.rename(dirpath, decrypted_newdirpath)
    return decrypted_newdirpath


def encryptModel (dirpath : str, key: bytes, guid : str, name_encryption = True):
    dirpath = normalizePath(dirpath)
    filesep = '\\' if os.name == "nt" else '/'
    contents = os.listdir(dirpath)
    for content in contents:
        if (os.path.isdir(dirpath+filesep+content)):
            contentdirpath = dirpath+filesep+content
            if (name_encryption):
                contentdirpath = encryptDirName(dirpath+filesep+content, key, guid)
            encryptModel(contentdirpath, key, guid, name_encryption)
        else:
            encryptFile(dirpath+filesep+content, key, guid, name_encryption)
    return SUCCESS           


def decryptModel (dirpath : str, key: bytes, guid : str, name_decryption = True):
    dirpath = normalizePath(dirpath)
    filesep = '\\' if os.name == "nt" else '/'
    contents = os.listdir(dirpath)
    for content in contents:
        if (os.path.isdir(dirpath+filesep+content)):
            contentdirpath = dirpath+filesep+content
            if (name_decryption):
                contentdirpath = decryptDirName(dirpath+filesep+content, key, guid)
            decryptModel(contentdirpath, key, guid, name_decryption)
        else:
            decryptFile(dirpath+filesep+content, key, guid, name_decryption)
    return SUCCESS


if (__name__ == "__main__"):
    path = input("Path = ")
    if (path.endswith(".py")):
        print ("Can't encrypt code!!!")
        raise SystemExit(1)
    guid = "1234567890"
    if (not os.path.isfile("keyfile")):
        key = secrets.token_bytes(32)
        with open("keyfile", "wb") as keyfile:
            keyfile.write(key)
    else:
        with open("keyfile", "rb") as keyfile:
            key = keyfile.read()
    choice = int(input("[1] Encrypt\n[2] Decrypt\nChoice: "))
    if (choice == 1):
        encryptModel(path, key, guid, False)
    elif (choice == 2):
        decryptModel(path, key, guid, False)
    else:
        print ("Illegal choice.")