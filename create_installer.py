import os
import shutil
from zipfile import ZipFile

def create_installer():
    # 创建发布目录
    release_dir = "APK网络分析工具"
    if os.path.exists(release_dir):
        shutil.rmtree(release_dir)
    os.makedirs(release_dir)
    os.makedirs(os.path.join(release_dir, "output"))
    os.makedirs(os.path.join(release_dir, "scripts"))
    os.makedirs(os.path.join(release_dir, "env"))
    
    # 使用正确的路径分隔符
    exe_path = os.path.join("dist", "APK网络分析工具.exe")
    
    # 检查文件是否存在
    if not os.path.exists(exe_path):
        print(f"错误: 找不到可执行文件: {exe_path}")
        return False
        
    try:
        # 复制主程序和配置文件
        shutil.copy(exe_path, release_dir)
        shutil.copy("config.json", release_dir)
        shutil.copy("check_env.bat", release_dir)
        
        # 复制 frida-server
        if os.path.exists("frida-server"):
            shutil.copy("frida-server", release_dir)
        else:
            print("警告: 找不到 frida-server 文件")
            
        # 复制 scripts 目录
        scripts_dir = os.path.join(release_dir, "scripts")
        if os.path.exists("scripts"):
            for file in os.listdir("scripts"):
                if file.endswith('.js'):
                    shutil.copy(os.path.join("scripts", file), scripts_dir)
        else:
            print("警告: 找不到 scripts 目录")
            
        # 复制环境文件
        env_dir = os.path.join(release_dir, "env")
        if os.path.exists("env"):
            for item in os.listdir("env"):
                src = os.path.join("env", item)
                dst = os.path.join(env_dir, item)
                if os.path.isfile(src):
                    shutil.copy2(src, dst)
                else:
                    shutil.copytree(src, dst)
        else:
            print("警告: 找不到 env 目录")
            
        # 创建 ZIP 包
        zip_name = 'APK网络分析工具_安装包.zip'
        with ZipFile(zip_name, 'w') as zipf:
            for root, dirs, files in os.walk(release_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, release_dir)
                    zipf.write(file_path, arcname)
                    
            # 确保空目录也被包含
            for root, dirs, files in os.walk(release_dir):
                for dir in dirs:
                    dir_path = os.path.join(root, dir)
                    arcname = os.path.relpath(dir_path, release_dir) + '/'
                    zipinfo = ZipFile.ZipInfo(arcname)
                    zipf.writestr(zipinfo, '')
        
        return True
            
    except Exception as e:
        print(f"创建安装包时出错: {str(e)}")
        return False

if __name__ == "__main__":
    if create_installer():
        print("安装包创建成功！")
    else:
        print("安装包创建失败！") 