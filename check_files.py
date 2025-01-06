import os

def check_files():
    base_path = os.path.dirname(os.path.abspath(__file__))
    
    # 检查必要文件
    files_to_check = [
        ('frida-server', ''),
        ('config.json', ''),
        ('network_monitor.js', 'scripts'),
    ]
    
    missing_files = []
    for file, subdir in files_to_check:
        path = os.path.join(base_path, subdir, file) if subdir else os.path.join(base_path, file)
        if not os.path.exists(path):
            missing_files.append(path)
            print(f"缺少文件: {path}")
        else:
            print(f"找到文件: {path}")
    
    if missing_files:
        print("\n缺少以下文件:")
        for file in missing_files:
            print(f"- {file}")
        return False
    
    print("\n所有必要文件都存在")
    return True

if __name__ == "__main__":
    check_files() 