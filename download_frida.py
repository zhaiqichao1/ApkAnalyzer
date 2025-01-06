import os
import requests
import sys
import platform

def download_frida_server():
    """下载frida-server"""
    try:
        # 获取最新的frida-server版本
        version = "16.1.4"  # 可以根据需要修改版本
        arch = "x86"  # 或 "arm", "arm64" 等
        
        # 构建下载URL
        url = f"https://github.com/frida/frida/releases/download/{version}/frida-server-{version}-android-{arch}"
        
        print(f"正在下载 frida-server {version}...")
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        # 保存文件
        with open("frida-server", "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        
        print("下载完成！")
        return True
        
    except Exception as e:
        print(f"下载失败: {str(e)}")
        return False

if __name__ == "__main__":
    if not os.path.exists("frida-server"):
        if download_frida_server():
            print("frida-server 已下载")
        else:
            print("frida-server 下载失败")
            sys.exit(1)
    else:
        print("frida-server 已存在") 