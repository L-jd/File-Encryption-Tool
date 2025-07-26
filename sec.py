from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os

# 用户密码（实际应让用户输入）
PASSWORD = b'qwer'

# 盐值（salt）：每次加密应不同，并保存在文件中
SALT = b'salt_12345678'

# 使用 PBKDF2 生成 32 字节的密钥
def generate_key(password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Fernet 要求密钥长度为 32 字节
        salt=SALT,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))  # 只 encode 一次

# 生成密钥并初始化 Fernet
KEY = Fernet(generate_key(PASSWORD))  # ✅ 只 encode 一次！

FILENAME = "teacher.txt"
MARKER = b"#ENCRYPTED#\n"

def is_encrypted():
    """检查文件是否已被加密"""
    if not os.path.exists(FILENAME):
        return False
    with open(FILENAME, "rb") as f:
        content = f.read(len(MARKER))
        return content == MARKER

def encrypt_file():
    """加密文件"""
    with open(FILENAME, "r", encoding="utf-8") as f:
        data = f.read().encode()

    encrypted_data = KEY.encrypt(data)

    with open(FILENAME, "wb") as f:
        f.write(MARKER)
        f.write(encrypted_data)

    print("文件已加密！")

def decrypt_file(password):
    """解密文件"""
    key = Fernet(generate_key(password))

    with open(FILENAME, "rb") as f:
        f.seek(len(MARKER))  # 跳过标记
        encrypted_data = f.read()

    try:
        decrypted_data = key.decrypt(encrypted_data)
        with open(FILENAME, "w", encoding="utf-8") as f:
            f.write(decrypted_data.decode())
        print("文件解密成功！")
    except Exception as e:
        print("密码错误，解密失败！", e)

def main():
    if not os.path.exists(FILENAME):
        print("文件不存在，请创建 teacher.txt 文件。")
        return

    if is_encrypted():
        # 已加密，要求输入密码
        password = input("文件已被加密，请输入密码：").strip()
        decrypt_file(password.encode())
    else:
        # 未加密，第一次运行，进行加密
        encrypt_file()
        print("文件已首次加密！")

if __name__ == "__main__":
    main()