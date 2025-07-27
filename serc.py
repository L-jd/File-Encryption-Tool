import os
import json
import hashlib
import getpass
from pathlib import Path
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
from tqdm import tqdm
import argparse

class UniversalFileEncryptor:
    def __init__(self):
        self.encrypted_extension = '.encrypted'
        self.metadata_file = '.encryption_metadata.json'
        self.excluded_files = {
            self.metadata_file,
            '.encryption_metadata.json.backup',
            'file_encryptor.py',
            '__pycache__',
            '.git',
            '.gitignore'
        }
        self.excluded_extensions = {
            '.py',  # Python脚本文件
            '.exe', # 可执行文件
            '.dll', # 动态链接库
            '.so',  # Linux共享对象
        }
    
    def generate_key(self, password: bytes, salt: bytes) -> Fernet:
        """基于密码和盐值生成加密密钥"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return Fernet(key)
    
    def generate_salt(self) -> bytes:
        """生成随机盐值"""
        return os.urandom(16)
    
    def calculate_file_hash(self, file_path: str) -> str:
        """计算文件SHA256哈希值"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception:
            return ""
    
    def should_encrypt_file(self, file_path: str) -> bool:
        """判断文件是否应该被加密"""
        file_name = os.path.basename(file_path)
        file_ext = Path(file_path).suffix.lower()
        
        # 跳过已加密文件
        if file_path.endswith(self.encrypted_extension):
            return False
        
        # 跳过排除的文件
        if file_name in self.excluded_files:
            return False
        
        # 跳过排除的扩展名
        if file_ext in self.excluded_extensions:
            return False
        
        # 跳过系统文件和隐藏文件（可选）
        if file_name.startswith('.') and file_name not in {'.env', '.config'}:
            return False
        
        return True
    
    def get_all_files(self, directory: str, recursive: bool = True) -> list:
        """获取目录下所有文件"""
        files = []
        
        if recursive:
            for root, dirs, filenames in os.walk(directory):
                # 跳过某些系统目录
                dirs[:] = [d for d in dirs if not d.startswith('.') or d in {'.config'}]
                
                for filename in filenames:
                    file_path = os.path.join(root, filename)
                    if self.should_encrypt_file(file_path):
                        files.append(file_path)
        else:
            for item in os.listdir(directory):
                file_path = os.path.join(directory, item)
                if os.path.isfile(file_path) and self.should_encrypt_file(file_path):
                    files.append(file_path)
        
        return files
    
    def encrypt_file_with_salt(self, file_path: str, key: Fernet, salt: bytes) -> dict:
        """加密单个文件，并在文件头部嵌入salt"""
        try:
            # 计算原文件哈希
            original_hash = self.calculate_file_hash(file_path)
            original_size = os.path.getsize(file_path)
            
            # 读取文件内容
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # 加密数据
            encrypted_data = key.encrypt(file_data)
            
            # 生成加密文件路径
            encrypted_path = file_path + self.encrypted_extension
            
            # 写入加密文件：salt + 分隔符 + 加密数据
            with open(encrypted_path, 'wb') as f:
                f.write(b'SALT:')  # 标识符
                f.write(base64.b64encode(salt))  # base64编码的salt
                f.write(b':DATA:')  # 分隔符
                f.write(encrypted_data)  # 加密数据
            
            # 删除原文件
            os.remove(file_path)
            
            return {
                'original_path': file_path,
                'encrypted_path': encrypted_path,
                'original_hash': original_hash,
                'original_size': original_size,
                'encrypted_size': len(encrypted_data),
                'status': 'success',
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'original_path': file_path,
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def encrypt_file(self, file_path: str, key: Fernet) -> dict:
        """加密单个文件（保持向后兼容）"""
        try:
            # 计算原文件哈希
            original_hash = self.calculate_file_hash(file_path)
            original_size = os.path.getsize(file_path)
            
            # 读取文件内容
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # 加密数据
            encrypted_data = key.encrypt(file_data)
            
            # 生成加密文件路径
            encrypted_path = file_path + self.encrypted_extension
            
            # 写入加密文件
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            # 删除原文件
            os.remove(file_path)
            
            return {
                'original_path': file_path,
                'encrypted_path': encrypted_path,
                'original_hash': original_hash,
                'original_size': original_size,
                'encrypted_size': len(encrypted_data),
                'status': 'success',
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'original_path': file_path,
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def extract_salt_from_file(self, encrypted_path: str) -> tuple:
        """从加密文件中提取salt和加密数据"""
        try:
            with open(encrypted_path, 'rb') as f:
                data = f.read()
            
            # 检查是否有salt标识符
            if data.startswith(b'SALT:'):
                # 新格式：包含salt
                try:
                    # 找到分隔符
                    salt_end = data.find(b':DATA:', 5)  # 从SALT:后开始查找
                    if salt_end == -1:
                        return None, data  # 格式错误，当作旧格式处理
                    
                    # 提取salt
                    salt_b64 = data[5:salt_end]  # 5是"SALT:"的长度
                    salt = base64.b64decode(salt_b64)
                    
                    # 提取加密数据
                    encrypted_data = data[salt_end + 6:]  # 6是":DATA:"的长度
                    
                    return salt, encrypted_data
                except Exception:
                    return None, data  # 解析失败，当作旧格式处理
            else:
                # 旧格式：没有salt
                return None, data
                
        except Exception as e:
            raise Exception(f"无法读取加密文件: {e}")
    
    def decrypt_file(self, encrypted_path: str, key: Fernet, verify_hash: str = None) -> dict:
        """解密单个文件"""
        try:
            # 提取salt和加密数据
            salt, encrypted_data = self.extract_salt_from_file(encrypted_path)
            
            # 解密数据
            decrypted_data = key.decrypt(encrypted_data)
            
            # 生成原文件路径
            original_path = encrypted_path.replace(self.encrypted_extension, '')
            
            # 写入解密文件
            with open(original_path, 'wb') as f:
                f.write(decrypted_data)
            
            # 验证文件完整性
            if verify_hash:
                current_hash = self.calculate_file_hash(original_path)
                if current_hash != verify_hash:
                    return {
                        'encrypted_path': encrypted_path,
                        'original_path': original_path,
                        'status': 'error',
                        'error': 'File integrity check failed',
                        'timestamp': datetime.now().isoformat()
                    }
            
            # 删除加密文件
            os.remove(encrypted_path)
            
            return {
                'encrypted_path': encrypted_path,
                'original_path': original_path,
                'status': 'success',
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'encrypted_path': encrypted_path,
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def decrypt_file_with_password(self, encrypted_path: str, password: str, verify_hash: str = None) -> dict:
        """使用密码解密单个文件（自动提取salt）"""
        try:
            # 提取salt和加密数据
            salt, encrypted_data = self.extract_salt_from_file(encrypted_path)
            
            if salt is None:
                return {
                    'encrypted_path': encrypted_path,
                    'status': 'error',
                    'error': 'Cannot extract salt from file. File may be encrypted with old version without embedded salt.',
                    'timestamp': datetime.now().isoformat()
                }
            
            # 使用提取的salt生成密钥
            key = self.generate_key(password.encode(), salt)
            
            # 解密数据
            decrypted_data = key.decrypt(encrypted_data)
            
            # 生成原文件路径
            original_path = encrypted_path.replace(self.encrypted_extension, '')
            
            # 写入解密文件
            with open(original_path, 'wb') as f:
                f.write(decrypted_data)
            
            # 验证文件完整性
            if verify_hash:
                current_hash = self.calculate_file_hash(original_path)
                if current_hash != verify_hash:
                    return {
                        'encrypted_path': encrypted_path,
                        'original_path': original_path,
                        'status': 'error',
                        'error': 'File integrity check failed',
                        'timestamp': datetime.now().isoformat()
                    }
            
            # 删除加密文件
            os.remove(encrypted_path)
            
            return {
                'encrypted_path': encrypted_path,
                'original_path': original_path,
                'status': 'success',
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'encrypted_path': encrypted_path,
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def save_metadata(self, metadata: dict, directory: str):
        """保存加密元数据"""
        metadata_path = os.path.join(directory, self.metadata_file)
        
        # 备份现有元数据
        if os.path.exists(metadata_path):
            backup_path = metadata_path + '.backup'
            try:
                with open(metadata_path, 'r', encoding='utf-8') as f:
                    backup_data = json.load(f)
                with open(backup_path, 'w', encoding='utf-8') as f:
                    json.dump(backup_data, f, indent=2, ensure_ascii=False)
            except Exception:
                pass
        
        # 保存新元数据
        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
    
    def load_metadata(self, directory: str) -> dict:
        """加载加密元数据"""
        metadata_path = os.path.join(directory, self.metadata_file)
        
        if not os.path.exists(metadata_path):
            return {}
        
        try:
            with open(metadata_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"[警告] 无法读取元数据文件: {e}")
            return {}
    
    def encrypt_directory(self, directory: str, password: str, recursive: bool = True):
        """加密整个目录的文件"""
        print(f"开始加密目录: {directory}")
        
        # 生成密钥和salt
        salt = self.generate_salt()
        key = self.generate_key(password.encode(), salt)
        
        # 获取所有需要加密的文件
        files = self.get_all_files(directory, recursive)
        
        if not files:
            print("未找到需要加密的文件")
            return
        
        print(f"找到 {len(files)} 个文件需要加密")
        
        # 准备元数据
        metadata = {
            'salt': base64.b64encode(salt).decode(),
            'timestamp': datetime.now().isoformat(),
            'total_files': len(files),
            'files': {},
            'statistics': {
                'successful': 0,
                'failed': 0,
                'total_original_size': 0,
                'total_encrypted_size': 0
            }
        }
        
        # 加密文件（使用新的方法，嵌入salt）
        successful = 0
        failed = 0
        
        for file_path in tqdm(files, desc="加密进度", unit="文件"):
            result = self.encrypt_file_with_salt(file_path, key, salt)
            metadata['files'][file_path] = result
            
            if result['status'] == 'success':
                successful += 1
                metadata['statistics']['total_original_size'] += result['original_size']
                metadata['statistics']['total_encrypted_size'] += result['encrypted_size']
                print(f"[✓] {file_path}")
            else:
                failed += 1
                print(f"[✗] {file_path}: {result.get('error', 'Unknown error')}")
        
        # 更新统计信息
        metadata['statistics']['successful'] = successful
        metadata['statistics']['failed'] = failed
        
        # 保存元数据
        self.save_metadata(metadata, directory)
        
        print(f"\n加密完成!")
        print(f"成功: {successful} 个文件")
        print(f"失败: {failed} 个文件")
        print(f"原始大小: {self._format_size(metadata['statistics']['total_original_size'])}")
        print(f"加密后大小: {self._format_size(metadata['statistics']['total_encrypted_size'])}")
    
    def decrypt_directory(self, directory: str, password: str):
        """解密整个目录的文件"""
        print(f"开始解密目录: {directory}")
        
        # 加载元数据
        metadata = self.load_metadata(directory)
        
        if not metadata:
            print("未找到加密元数据，尝试搜索加密文件...")
            # 搜索.encrypted文件
            encrypted_files = []
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if file.endswith(self.encrypted_extension):
                        encrypted_files.append(os.path.join(root, file))
            
            if not encrypted_files:
                print("未找到任何加密文件")
                return
            
            print(f"找到 {len(encrypted_files)} 个加密文件")
            print("将尝试从文件中提取salt进行解密...")
            
            # 直接解密文件（从文件中提取salt）
            successful = 0
            failed = 0
            
            for encrypted_path in tqdm(encrypted_files, desc="解密进度", unit="文件"):
                result = self.decrypt_file_with_password(encrypted_path, password)
                
                if result['status'] == 'success':
                    successful += 1
                    print(f"[✓] {result['original_path']}")
                else:
                    failed += 1
                    print(f"[✗] {encrypted_path}: {result.get('error', 'Unknown error')}")
            
            print(f"\n解密完成!")
            print(f"成功: {successful} 个文件")
            print(f"失败: {failed} 个文件")
            return
        
        # 有元数据的情况
        # 生成密钥
        salt = base64.b64decode(metadata['salt'])
        key = self.generate_key(password.encode(), salt)
        
        # 获取所有加密文件
        encrypted_files = []
        for original_path, file_info in metadata['files'].items():
            if file_info.get('status') == 'success':
                encrypted_path = file_info.get('encrypted_path', original_path + self.encrypted_extension)
                if os.path.exists(encrypted_path):
                    encrypted_files.append((encrypted_path, file_info.get('original_hash')))
        
        if not encrypted_files:
            print("未找到需要解密的文件")
            return
        
        print(f"找到 {len(encrypted_files)} 个文件需要解密")
        
        # 解密文件
        successful = 0
        failed = 0
        
        for encrypted_path, original_hash in tqdm(encrypted_files, desc="解密进度", unit="文件"):
            result = self.decrypt_file(encrypted_path, key, original_hash)
            
            if result['status'] == 'success':
                successful += 1
                print(f"[✓] {result['original_path']}")
            else:
                failed += 1
                print(f"[✗] {encrypted_path}: {result.get('error', 'Unknown error')}")
        
        print(f"\n解密完成!")
        print(f"成功: {successful} 个文件")
        print(f"失败: {failed} 个文件")
        
        # 清理元数据文件
        metadata_path = os.path.join(directory, self.metadata_file)
        if os.path.exists(metadata_path):
            os.remove(metadata_path)
            print("已清理加密元数据")
    
    def _format_size(self, size_bytes: int) -> str:
        """格式化文件大小"""
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        
        return f"{size_bytes:.2f} {size_names[i]}"
    
    def list_encrypted_files(self, directory: str):
        """列出加密文件信息"""
        metadata = self.load_metadata(directory)
        
        if not metadata:
            print("未找到加密元数据")
            return
        
        print(f"\n=== 加密文件信息 ===")
        print(f"加密时间: {metadata.get('timestamp', 'Unknown')}")
        print(f"总文件数: {metadata.get('total_files', 0)}")
        
        stats = metadata.get('statistics', {})
        print(f"成功加密: {stats.get('successful', 0)}")
        print(f"加密失败: {stats.get('failed', 0)}")
        print(f"原始总大小: {self._format_size(stats.get('total_original_size', 0))}")
        print(f"加密后总大小: {self._format_size(stats.get('total_encrypted_size', 0))}")
        
        print(f"\n文件列表:")
        for original_path, file_info in metadata.get('files', {}).items():
            status = "✓" if file_info.get('status') == 'success' else "✗"
            size = self._format_size(file_info.get('original_size', 0))
            print(f"  {status} {original_path} ({size})")

def main():
    parser = argparse.ArgumentParser(description='通用文件加密工具')
    parser.add_argument('action', choices=['encrypt', 'decrypt', 'list'], 
                       help='操作类型: encrypt(加密), decrypt(解密), list(列出加密文件)')
    parser.add_argument('-d', '--directory', default='.', 
                       help='目标目录 (默认: 当前目录)')
    parser.add_argument('-r', '--recursive', action='store_true', 
                       help='递归处理子目录')
    parser.add_argument('-p', '--password', 
                       help='密码 (如果未提供，将提示输入)')
    
    args = parser.parse_args()
    
    encryptor = UniversalFileEncryptor()
    
    # 获取密码
    if args.action in ['encrypt', 'decrypt']:
        if args.password:
            password = args.password
        else:
            password = getpass.getpass("请输入密码: ")
        
        if not password:
            print("密码不能为空")
            return
    
    # 执行操作
    try:
        if args.action == 'encrypt':
            encryptor.encrypt_directory(args.directory, password, args.recursive)
        elif args.action == 'decrypt':
            encryptor.decrypt_directory(args.directory, password)
        elif args.action == 'list':
            encryptor.list_encrypted_files(args.directory)
    
    except KeyboardInterrupt:
        print("\n操作被用户中断")
    except Exception as e:
        print(f"操作失败: {e}")

if __name__ == "__main__":
    # 如果没有命令行参数，使用交互模式
    import sys
    if len(sys.argv) == 1:
        encryptor = UniversalFileEncryptor()
        
        print("=== 通用文件加密工具 ===")
        print("1. 加密当前目录所有文件")
        print("2. 加密当前目录所有文件(包含子目录)")
        print("3. 解密当前目录所有文件")
        print("4. 列出加密文件信息")
        print("5. 自定义目录操作")
        
        choice = input("\n请选择操作 (1-5): ").strip()
        
        if choice == "1":
            password = getpass.getpass("请输入加密密码: ")
            encryptor.encrypt_directory(".", password, recursive=False)
        
        elif choice == "2":
            password = getpass.getpass("请输入加密密码: ")
            encryptor.encrypt_directory(".", password, recursive=True)
        
        elif choice == "3":
            password = getpass.getpass("请输入解密密码: ")
            encryptor.decrypt_directory(".", password)
        
        elif choice == "4":
            encryptor.list_encrypted_files(".")
        
        elif choice == "5":
            directory = input("请输入目录路径: ").strip() or "."
            action = input("请选择操作 (encrypt/decrypt/list): ").strip().lower()
            
            if action in ["encrypt", "decrypt"]:
                password = getpass.getpass("请输入密码: ")
                recursive = input("是否递归处理子目录? (y/N): ").strip().lower() == 'y'
                
                if action == "encrypt":
                    encryptor.encrypt_directory(directory, password, recursive)
                else:
                    encryptor.decrypt_directory(directory, password)
            
            elif action == "list":
                encryptor.list_encrypted_files(directory)
            
            else:
                print("无效的操作")
        
        else:
            print("无效的选择")
    
    else:
        main()