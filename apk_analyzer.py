import frida
import subprocess
import json
import requests
import hashlib
import os
import re
import socket
import time
from datetime import datetime
import sys
from urllib.parse import urlparse
import dns.resolver

class ApkAnalyzer:
    def __init__(self):
        self.nox_path = ""
        self.output_dir = "output"
        self.results = None
        self.adb_path = None
        self.progress_callback = None
        self.config_file = "config.json"
        self.config = {}  # 添加config属性
        self.request_set = set()  # 用于存储已处理的请求
        
        # 创建输出目录
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        
        # 加载配置
        self.load_config()
        
    def load_config(self):
        """加载配置文件"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
                    if 'nox_path' in self.config and os.path.exists(self.config['nox_path']):
                        self.nox_path = self.config['nox_path']
                        self.adb_path = os.path.join(self.nox_path, "nox_adb.exe")
        except Exception as e:
            print(f"加载配置文件时出错: {str(e)}")
            self.config = {
                'nox_path': '',
                'output_dir': 'output'
            }
        
    def save_config(self):
        """保存配置文件"""
        try:
            self.config.update({
                'nox_path': self.nox_path,
                'output_dir': self.output_dir
            })
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"保存配置文件时出错: {str(e)}")
        
    def setup_environment(self):
        """安装必要的依赖并检查环境"""
        try:
            # 检查 frida 是否已安装
            import frida
            
            # 检查 frida-tools 是否已安装
            try:
                import frida_tools
            except ImportError:
                print("frida-tools 未安装")
                return False
            
            # 检查 frida-server
            base_path = os.path.dirname(os.path.abspath(__file__))
            server_path = os.path.join(base_path, 'frida-server')
            print(f"检查 frida-server: {server_path}")
            if not os.path.exists(server_path):
                print("frida-server 不存在")
                return False
            
            # 检查 aapt
            try:
                # 首先检查环境变量中的 AAPT_PATH
                if 'AAPT_PATH' in os.environ:
                    subprocess.check_output([os.environ['AAPT_PATH'], 'version'])
                    print("找到 AAPT_PATH")
                else:
                    # 尝试在 Android SDK 目录下查找 aapt
                    sdk_paths = [
                        os.path.join(os.environ.get('ANDROID_HOME', ''), 'build-tools'),
                        os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Android', 'Sdk', 'build-tools'),
                        os.path.join(os.environ.get('PROGRAMFILES', ''), 'Android', 'android-sdk', 'build-tools'),
                        os.path.join(os.environ.get('PROGRAMFILES(X86)', ''), 'Android', 'android-sdk', 'build-tools'),
                    ]
                    
                    for sdk_path in sdk_paths:
                        if os.path.exists(sdk_path):
                            versions = os.listdir(sdk_path)
                            versions.sort(reverse=True)
                            for version in versions:
                                aapt_path = os.path.join(sdk_path, version, 'aapt.exe')
                                if os.path.exists(aapt_path):
                                    os.environ['AAPT_PATH'] = aapt_path
                                    print(f"找到 aapt: {aapt_path}")
                                    break
                            if 'AAPT_PATH' in os.environ:
                                break
                    
                    if 'AAPT_PATH' not in os.environ:
                        print("警告: 未找到 aapt，将使用备选方案获取包名")
            except:
                print("警告: aapt 检查失败，将使用备选方案获取包名")
            
            return True
            
        except ImportError:
            print("frida 未安装")
            return False
        except Exception as e:
            print(f"设置环境时出错: {str(e)}")
            return False

    def _download_frida_server(self, version, abi):
        """下载对应版本的frida-server"""
        try:
            # 映射Android ABI到frida-server文件名
            abi_map = {
                'armeabi-v7a': 'arm',
                'arm64-v8a': 'arm64',
                'x86': 'x86',
                'x86_64': 'x86_64'
            }
            
            if abi not in abi_map:
                print(f"不支持的设备架构: {abi}")
                return None
            
            frida_arch = abi_map[abi]
            version = version.strip()
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            # 获取所有版本
            print("获取可用版本列表...")
            releases_url = 'https://api.github.com/repos/frida/frida/releases'
            response = requests.get(releases_url, headers=headers)
            
            if response.status_code != 200:
                print(f"获取版本列表失败: HTTP {response.status_code}")
                return None
            
            releases = response.json()
            
            # 查找匹配的版本
            target_version = None
            for release in releases:
                if release['tag_name'].lstrip('v') == version:
                    target_version = release['tag_name']
                    break
                
            if not target_version:
                print(f"未找到版本 {version}，使用最新版本")
                target_version = releases[0]['tag_name']
            
            print(f"使用版本: {target_version}")
            
            # 构建下载文件名
            server_name = f'frida-server-{target_version.lstrip("v")}-android-{frida_arch}'
            server_path = os.path.join(os.path.dirname(__file__), 'frida-server')
            
            # 如果已存在且版本正确，直接返回
            if os.path.exists(server_path):
                try:
                    result = subprocess.run([self.adb_path, 'shell', '/data/local/tmp/frida-server --version'], 
                                         capture_output=True, text=True)
                    if target_version.lstrip('v') in result.stdout:
                        print("已存在正确版本的frida-server")
                        return server_path
                except:
                    pass
            
            # 下载frida-server
            print(f"正在下载 {server_name}...")
            
            # 在release的assets中查找对应文件
            asset_url = None
            for release in releases:
                if release['tag_name'] == target_version:
                    for asset in release['assets']:
                        if asset['name'] == f'{server_name}.xz':
                            asset_url = asset['browser_download_url']
                            break
                    break
            
            if not asset_url:
                print(f"未找到对应的下载文件")
                return None
            
            print(f"下载地址: {asset_url}")
            response = requests.get(asset_url, headers=headers, allow_redirects=True)
            
            if response.status_code != 200:
                print(f"下载失败: HTTP {response.status_code}")
                return None
            
            # 保存并解压
            xz_path = f'{server_path}.xz'
            with open(xz_path, 'wb') as f:
                f.write(response.content)
            
            try:
                import lzma
                with lzma.open(xz_path) as f_in:
                    with open(server_path, 'wb') as f_out:
                        f_out.write(f_in.read())
            
                os.remove(xz_path)
                print("frida-server下载完成")
                
                # 设置执行权限
                os.chmod(server_path, 0o755)
                return server_path
                
            except Exception as e:
                print(f"解压frida-server时出错: {str(e)}")
                if os.path.exists(xz_path):
                    os.remove(xz_path)
                return None
            
        except Exception as e:
            print(f"下载frida-server时出错: {str(e)}")
            return None

    def set_nox_path(self, path):
        """设置夜神模拟器路径"""
        if not os.path.exists(path):
            print("错误: 指定的夜神模拟器路径不存在")
            return False
        self.nox_path = path
        self.adb_path = os.path.join(self.nox_path, "nox_adb.exe")
        self.save_config()  # 保存配置
        return True
        
    def connect_emulator(self):
        """连接夜神模拟器"""
        try:
            print("正在连接模拟器...")
            
            # 先检查 adb 是否可用
            try:
                version_result = subprocess.run([self.adb_path, 'version'], 
                                             capture_output=True, text=True, timeout=5)
                print(f"ADB 版本: {version_result.stdout.strip()}")
            except Exception as e:
                print(f"检查 ADB 失败: {str(e)}")
                return False
            
            # 先关闭可能存在的ADB服务
            try:
                subprocess.run([self.adb_path, 'kill-server'], 
                             capture_output=True, timeout=5)
                time.sleep(2)
            except:
                pass
            
            # 启动ADB服务
            try:
                subprocess.run([self.adb_path, 'start-server'], 
                             capture_output=True, timeout=5)
                time.sleep(2)
            except:
                pass
            
            # 尝试多个常用端口
            ports = ['62001', '62025', '62026', '5555']
            
            for port in ports:
                try:
                    print(f"\n尝试连接端口 {port}...")
                    
                    # 先断开可能的连接
                    subprocess.run([self.adb_path, 'disconnect', f'127.0.0.1:{port}'],
                                 capture_output=True, timeout=5)
                    time.sleep(1)
                    
                    # 连接模拟器
                    connect_result = subprocess.run([self.adb_path, 'connect', f'127.0.0.1:{port}'],
                                                 capture_output=True, text=True, timeout=5)
                    print(f"连接结果: {connect_result.stdout.strip()}")
                    
                    if 'connected' in connect_result.stdout.lower():
                        # 检查设备连接状态
                        devices_result = subprocess.run([self.adb_path, 'devices'],
                                                     capture_output=True, text=True, timeout=5)
                        print(f"设备列表:\n{devices_result.stdout.strip()}")
                        
                        if f'127.0.0.1:{port}' in devices_result.stdout:
                            print(f"模拟器连接成功 (端口 {port})")
                            return True
                except Exception as e:
                    print(f"尝试端口 {port} 失败: {str(e)}")
                    continue
            
            print("\n所有端口连接尝试都失败")
            return False
            
        except Exception as e:
            print(f"连接模拟器时出错: {str(e)}")
            return False

    def analyze_apk(self, apk_path):
        """分析单个APK文件"""
        try:
            print(f"\n开始分析APK: {os.path.basename(apk_path)}")
            
            # 检查文件是否存在
            if not os.path.exists(apk_path):
                raise Exception("APK文件不存在")
            
            # 计算文件hash
            file_hash = self._calculate_hash(apk_path)
            print(f"文件Hash: {file_hash}")
            
            # 清空请求集合
            self.request_set.clear()
            
            # 初始化结果
            self.results = {
                'file_name': os.path.basename(apk_path),
                'hash': file_hash,
                'requests': []
            }
            
            # 获取安装前的包列表
            print("\n获取安装前的包列表...")
            before_install = set()
            try:
                result = subprocess.run([self.adb_path, 'shell', 'pm', 'list', 'packages'],
                                     capture_output=True, text=True, check=True)
                before_install = set(result.stdout.splitlines())
            except Exception as e:
                print(f"获取包列表失败: {str(e)}")
            
            # 安装APK
            print("\n正在安装APK...")
            try:
                result = subprocess.run([self.adb_path, 'install', '-r', apk_path], 
                                     capture_output=True, text=True, check=True)
                print(f"安装输出: {result.stdout}")
            except subprocess.CalledProcessError as e:
                raise Exception(f"APK安装失败: {e.stdout}\n{e.stderr}")
            
            # 等待安装完成
            time.sleep(2)
            
            # 获取包名
            print("\n获取包名...")
            try:
                package_name = None
                
                # 获取安装后的包列表
                after_install = set()
                result = subprocess.run([self.adb_path, 'shell', 'pm', 'list', 'packages'],
                                     capture_output=True, text=True, check=True)
                after_install = set(result.stdout.splitlines())
                
                # 找出新增的包
                new_packages = after_install - before_install
                if new_packages:
                    # 提取包名
                    package_name = new_packages.pop().replace('package:', '')
                    print(f"找到新安装的包名: {package_name}")
                
                # 如果上面的方法失败，尝试使用 dumpsys package 命令
                if not package_name:
                    print("尝试使用 dumpsys package 获取包名...")
                    result = subprocess.run([self.adb_path, 'shell', 'dumpsys', 'package', '|', 'grep', '"pkg.name="'],
                                         capture_output=True, text=True, shell=True)
                    packages = result.stdout.splitlines()
                    # 获取最后一个安装的包
                    if packages:
                        last_package = packages[-1]
                        match = re.search(r'pkg.name=([^\s]+)', last_package)
                        if match:
                            package_name = match.group(1)
                            print(f"通过 dumpsys 找到包名: {package_name}")
                
                # 如果还是失败，尝试从文件名猜测包名
                if not package_name:
                    base_name = os.path.splitext(os.path.basename(apk_path))[0]
                    if '.' in base_name:  # 如果文件名包含点号，可能是包名格式
                        package_name = base_name
                        print(f"从文件名猜测包名: {package_name}")
                
                if not package_name:
                    raise Exception("无法获取包名")
                
                # 验证包名是否正确
                print(f"\n验证包名: {package_name}")
                result = subprocess.run([self.adb_path, 'shell', f'pm', 'path', package_name],
                                     capture_output=True, text=True)
                if 'package:' not in result.stdout:
                    raise Exception("包名验证失败")
                
                print(f"包名验证成功: {package_name}")
                
            except Exception as e:
                raise Exception(f"获取包名失败: {str(e)}")
            
            # 确保应用已停止
            print("\n停止应用...")
            subprocess.run([self.adb_path, 'shell', f'am force-stop {package_name}'])
            time.sleep(2)  # 等待应用完全停止
            
            # 在启动应用前，先自动授予所有权限
            print("\n自动授予权限...")
            try:
                # 获取应用的所有权限
                result = subprocess.run([self.adb_path, 'shell', f'dumpsys package {package_name} | grep permission'],
                                     capture_output=True, text=True)
                
                # 解析权限列表
                permissions = []
                for line in result.stdout.splitlines():
                    if 'android.permission.' in line:
                        perm = line.strip().split(':')[0].strip()
                        permissions.append(perm)
                
                # 批量授予权限
                for permission in permissions:
                    try:
                        subprocess.run([self.adb_path, 'shell', f'pm grant {package_name} {permission}'],
                                     capture_output=True, timeout=2)
                    except:
                        continue
                
                print(f"已授予 {len(permissions)} 个权限")
                
                # 额外处理一些特殊权限
                special_permissions = [
                    'android.permission.SYSTEM_ALERT_WINDOW',
                    'android.permission.WRITE_SETTINGS',
                    'android.permission.PACKAGE_USAGE_STATS'
                ]
                
                for perm in special_permissions:
                    try:
                        subprocess.run([self.adb_path, 'shell', f'appops set {package_name} {perm} allow'],
                                     capture_output=True, timeout=2)
                    except:
                        continue
                
            except Exception as e:
                print(f"授予权限时出错: {str(e)}")
            
            # 启动应用前先关闭可能的弹窗
            print("\n处理系统弹窗...")
            try:
                # 关闭权限弹窗
                subprocess.run([self.adb_path, 'shell', 'input keyevent 4'], timeout=1)  # 返回键
                time.sleep(0.5)
                subprocess.run([self.adb_path, 'shell', 'input keyevent 66'], timeout=1)  # 确认键
                time.sleep(0.5)
                
                # 点击允许按钮位置
                subprocess.run([self.adb_path, 'shell', 'input tap 900 1200'], timeout=1)
                time.sleep(0.5)
                
                # 再次尝试关闭
                subprocess.run([self.adb_path, 'shell', 'input keyevent 4'], timeout=1)
            except:
                pass
            
            # 启动应用
            print("\n启动应用...")
            try:
                # 获取启动Activity
                result = subprocess.run([self.adb_path, 'shell', f'cmd package resolve-activity --brief {package_name} | tail -n 1'],
                                     capture_output=True, text=True, check=True)
                activity = result.stdout.strip()
                if not activity:
                    raise Exception("找不到启动Activity")
                
                # 使用 monkey 启动应用（可以绕过一些系统弹窗）
                subprocess.run([self.adb_path, 'shell', f'monkey -p {package_name} -c android.intent.category.LAUNCHER 1'],
                             capture_output=True, check=True)
                
                # 等待应用启动
                time.sleep(5)
                
                # 再次处理可能的弹窗
                try:
                    subprocess.run([self.adb_path, 'shell', 'input keyevent 4'], timeout=1)
                    time.sleep(0.5)
                    subprocess.run([self.adb_path, 'shell', 'input tap 900 1200'], timeout=1)
                except:
                    pass
                
            except subprocess.CalledProcessError as e:
                raise Exception(f"应用启动失败: {e.stdout}\n{e.stderr}")
            
            # 注入frida脚本监控网络请求
            print("\n注入监控脚本...")
            script = self._inject_frida_script()
            if not script:
                raise Exception("Frida脚本注入失败")
            
            # 等待一段时间收集数据
            print("\n正在收集网络请求数据...")
            total_time = 30  # 总等待时间
            for i in range(total_time):
                print(f"已收集 {i+1}/{total_time} 秒，发现 {len(self.results['requests'])} 个请求", end='\r')
                time.sleep(1)
            print("\n")  # 换行
            
            # 停止监控
            print("停止监控...")
            script.unload()
            
            # 停止并卸载应用
            print("\n清理环境...")
            try:
                # 先停止应用
                subprocess.run([self.adb_path, 'shell', f'am force-stop {package_name}'])
                time.sleep(1)
                
                # 尝试卸载
                try:
                    result = subprocess.run([self.adb_path, 'uninstall', package_name],
                                         capture_output=True, text=True)
                    if "Success" not in result.stdout:
                        # 如果普通卸载失败，尝试使用 pm uninstall
                        subprocess.run([self.adb_path, 'shell', f'pm uninstall {package_name}'],
                                     capture_output=True, text=True)
                except:
                    # 如果还是失败，尝试使用 pm uninstall -k
                    try:
                        subprocess.run([self.adb_path, 'shell', f'pm uninstall -k {package_name}'],
                                     capture_output=True, text=True)
                    except:
                        print(f"警告: 无法卸载应用 {package_name}")
            except Exception as e:
                print(f"清理环境时出错: {str(e)}")
            
            # 检查结果
            if not self.results['requests']:
                print("警告: 未发现任何网络请求")
            else:
                print(f"分析完成，共发现 {len(self.results['requests'])} 个网络请求")
            
            # 添加APK文件信息到结果中
            self.results['file_name'] = apk_path
            self.results['hash'] = self._calculate_hash(apk_path)
            
            # 添加分析时间
            self.results['analysis_time'] = datetime.now().isoformat()
            
            return self.results
            
        except Exception as e:
            print(f"\n分析APK时出错: {str(e)}")
            # 尝试清理
            try:
                if 'package_name' in locals():
                    try:
                        subprocess.run([self.adb_path, 'shell', f'am force-stop {package_name}'])
                        subprocess.run([self.adb_path, 'shell', f'pm uninstall {package_name}'])
                    except:
                        pass
            except:
                pass
            return None
    
    def _calculate_hash(self, file_path):
        """计算文件MD5值"""
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest() 

    def _get_ip_info(self, ip):
        """获取IP地址信息"""
        try:
            # 使用 ip-api.com 的免费API
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    return {
                        'country': data.get('country', 'Unknown'),
                        'region': data.get('regionName', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'isp': data.get('isp', 'Unknown'),
                        'org': data.get('org', 'Unknown')
                    }
        except Exception as e:
            print(f"获取IP信息时出错: {str(e)}")
            
        # 如果请求失败，返回默认值
        return {
            'country': 'Unknown',
            'region': 'Unknown',
            'city': 'Unknown',
            'isp': 'Unknown',
            'org': 'Unknown'
        }

    def _inject_frida_script(self):
        """注入Frida脚本"""
        try:
            # 等待设备连接
            print("等待设备连接...")
            for _ in range(3):  # 尝试3次
                try:
                    # 先尝试获取USB设备
                    device = frida.get_usb_device(timeout=5)
                    break
                except frida.TimedOutError:
                    # 如果USB连接失败，尝试通过网络连接
                    try:
                        device = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
                        break
                    except:
                        print("尝试重新连接设备...")
                        time.sleep(2)
            else:
                raise Exception("无法连接到设备")

            # 确保frida-server正在运行
            try:
                subprocess.run([self.adb_path, 'shell', 'ps | grep frida-server'], check=True)

            except:
                print("正在启动frida-server...")
                try:
                    # 推送frida-server到设备
                    server_path = os.path.join(os.path.dirname(__file__), 'frida-server')
                    if os.path.exists(server_path):
                        subprocess.run([self.adb_path, 'push', server_path, '/data/local/tmp/'], check=True)
                        subprocess.run([self.adb_path, 'shell', 'chmod 755 /data/local/tmp/frida-server'], check=True)
                        subprocess.run([self.adb_path, 'shell', '/data/local/tmp/frida-server &'], check=True)
                        time.sleep(2)  # 等待服务器启动
                    else:
                        raise Exception("找不到frida-server文件")
                except Exception as e:
                    raise Exception(f"启动frida-server失败: {str(e)}")

            # 等待应用启动
            print("等待应用启动...")
            for _ in range(10):  # 最多等待10秒
                front_app = device.get_frontmost_application()
                if front_app:
                    break
                time.sleep(1)
            else:
                raise Exception("无法获取前台应用")

            # 读取脚本内容
            script_path = os.path.join(os.path.dirname(__file__), 'scripts', 'network_monitor.js')
            if not os.path.exists(script_path):
                raise Exception("找不到监控脚本文件")
            
            with open(script_path, 'r', encoding='utf-8') as f:
                script_content = f.read()

            # 附加到进程
            session = device.attach(front_app.pid)
            
            # 创建脚本
            script = session.create_script(script_content)
            
            # 处理消息回调
            def on_message(message, data):
                if message['type'] == 'send':
                    payload = message['payload']
                    if payload['type'] == 'url':
                        self._process_url_request(payload)
                    elif payload['type'] == 'socket':
                        self._process_socket_request(payload)
                    elif payload['type'] == 'websocket':
                        self._process_websocket_request(payload)
                    elif payload['type'] == 'network':  # 添加网络连接处理
                        self._process_network_request(payload)
                elif message['type'] == 'error':
                    print(f"Frida脚本错误: {message['description']}")
                
            script.on('message', on_message)
            script.load()
            return script
            
        except Exception as e:
            print(f"注入Frida脚本时出错: {str(e)}")
            return None

    def _process_url_request(self, payload):
        try:
            url = payload.get('url', '')
            host = payload.get('host', '')
            
            # 如果没有host，尝试从URL解析
            if not host and url:
                try:
                    parsed = urlparse(url)
                    host = parsed.hostname or ''
                except:
                    pass
            
            # 如果还是没有host，可能是IP直接访问
            if not host and url:
                # 尝试从URL中提取IP地址
                ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
                ip_match = ip_pattern.search(url)
                if ip_match:
                    host = ip_match.group(1)
            
            if not host:
                print(f"警告: 无法获取host信息 - payload: {payload}")
                host = "Unknown"
            
            # 解析IP
            ip = None
            if self._is_ip(host):
                ip = host
            else:
                try:
                    ip = socket.gethostbyname(host)
                except:
                    # 如果DNS解析失败，尝试其他方法获取IP
                    try:
                        # 尝试异步DNS解析
                        resolver = dns.resolver.Resolver()
                        resolver.timeout = 3
                        resolver.lifetime = 3
                        answers = resolver.resolve(host, 'A')
                        if answers:
                            ip = answers[0].address
                    except:
                        ip = "Unknown"
            
            # 生成唯一标识
            unique_id = f"{host}-{ip}-{payload.get('type', '')}"
            
            # 如果已经处理过该请求，则跳过
            if unique_id in self.request_set:
                return
            
            # 添加到已处理集合
            self.request_set.add(unique_id)
            
            # 获取IP信息
            ip_info = self._get_ip_info(ip) if ip and ip != "Unknown" else {
                'country': 'Unknown',
                'region': 'Unknown',
                'city': 'Unknown',
                'isp': 'Unknown',
                'org': 'Unknown'
            }
            
            request_info = {
                'domain': host if not self._is_ip(host) else "",
                'ip': ip or "Unknown",
                'port': str(payload.get('port', '80')),
                'timestamp': payload.get('timestamp', datetime.now().isoformat()),
                'country': ip_info.get('country', 'Unknown'),
                'region': ip_info.get('region', 'Unknown'),
                'city': ip_info.get('city', 'Unknown'),
                'isp': ip_info.get('isp', 'Unknown'),
                'org': ip_info.get('org', 'Unknown')
            }
            
            # 处理 WebView 请求
            if payload.get('type') == 'webview':
                request_info['type'] = 'WebView'
                request_info['subtype'] = payload.get('subtype', '')
                request_info['method'] = payload.get('method', '')
                request_info['headers'] = payload.get('headers', '')
                
                # 如果是 WebView 请求，尝试从 URL 中提取更多信息
                if url:
                    try:
                        parsed = urlparse(url)
                        if not host and parsed.netloc:
                            host = parsed.netloc
                            # 更新域名相关信息
                            request_info['domain'] = host if not self._is_ip(host) else ""
                            if not ip or ip == "Unknown":
                                try:
                                    ip = socket.gethostbyname(host)
                                    request_info['ip'] = ip
                                except:
                                    pass
                    except:
                        pass

            # 添加到结果列表
            if not hasattr(self, 'results') or self.results is None:
                self.results = {'requests': []}
            self.results['requests'].append(request_info)
            
            # 回调更新界面
            if self.progress_callback:
                self.progress_callback(request_info)
            
            # 每收集到新的请求就自动保存
            try:
                if hasattr(self, 'last_save_time'):
                    # 每30秒自动保存一次
                    if (datetime.now() - self.last_save_time).total_seconds() > 30:
                        self._auto_save_results()
                else:
                    self.last_save_time = datetime.now()
            except:
                pass
            
        except Exception as e:
            print(f"处理URL请求时出错: {str(e)}")
            print(f"Payload: {payload}")

    def _process_socket_request(self, payload):
        """处理Socket请求"""
        try:
            host = payload['host']
            port = payload['port']
            
            # 解析IP
            try:
                ip = socket.gethostbyname(host)
            except:
                ip = host if self._is_ip(host) else "Unknown"
                
            # 生成唯一标识
            unique_id = f"{host}-{ip}"
            
            # 如果已经处理过该请求，则跳过
            if unique_id in self.request_set:
                return
                
            # 添加到已处理集合
            self.request_set.add(unique_id)
            
            # 获取IP信息
            ip_info = self._get_ip_info(ip)
            
            # 确保时间戳格式正确
            try:
                timestamp = payload.get('timestamp', '')
                if isinstance(timestamp, str) and 'Z' in timestamp:
                    from datetime import datetime
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    timestamp = dt.isoformat()
            except:
                from datetime import datetime
                timestamp = datetime.now().isoformat()
            
            request_info = {
                'domain': host if not self._is_ip(host) else "",
                'ip': ip,
                'port': str(port),  # 转换为字符串
                'timestamp': timestamp,
                'country': ip_info.get('country', 'Unknown'),
                'region': ip_info.get('region', 'Unknown'),
                'city': ip_info.get('city', 'Unknown'),
                'isp': ip_info.get('isp', 'Unknown'),
                'org': ip_info.get('org', 'Unknown')
            }
            
            # 添加到结果列表
            if not hasattr(self, 'results') or self.results is None:
                self.results = {'requests': []}
            if 'requests' not in self.results:
                self.results['requests'] = []
            self.results['requests'].append(request_info)
            
            # 回调更新界面
            if self.progress_callback:
                self.progress_callback(request_info)
            
        except Exception as e:
            print(f"处理Socket请求时出错: {str(e)}")
            print(f"Payload: {payload}")

    def _process_websocket_request(self, payload):
        """处理 WebSocket 请求"""
        try:
            url = payload.get('url', '')
            
            # 解析 WebSocket URL
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                host = parsed.hostname or ''
                port = str(parsed.port or ('443' if parsed.scheme == 'wss' else '80'))
                scheme = parsed.scheme
            except:
                host = ''
                port = ''
                scheme = ''
            
            if not host:
                print(f"警告: 无法解析WebSocket URL - {url}")
                return
            
            # 解析IP
            try:
                ip = socket.gethostbyname(host)
            except:
                ip = "Unknown"
            
            # 生成唯一标识
            unique_id = f"ws-{host}-{ip}-{port}"
            
            # 如果已经处理过该请求，则跳过
            if unique_id in self.request_set:
                return
            
            # 添加到已处理集合
            self.request_set.add(unique_id)
            
            # 获取IP信息
            ip_info = self._get_ip_info(ip) if ip != "Unknown" else {
                'country': 'Unknown',
                'region': 'Unknown',
                'city': 'Unknown',
                'isp': 'Unknown',
                'org': 'Unknown'
            }
            
            request_info = {
                'type': 'WebSocket',
                'subtype': payload.get('subtype', ''),
                'domain': host,
                'ip': ip,
                'port': port,
                'scheme': scheme,
                'url': url,
                'timestamp': payload.get('timestamp', datetime.now().isoformat()),
                'country': ip_info.get('country', 'Unknown'),
                'region': ip_info.get('region', 'Unknown'),
                'city': ip_info.get('city', 'Unknown'),
                'isp': ip_info.get('isp', 'Unknown'),
                'org': ip_info.get('org', 'Unknown')
            }
            
            # 添加到结果列表
            if not hasattr(self, 'results') or self.results is None:
                self.results = {'requests': []}
            self.results['requests'].append(request_info)
            
            # 回调更新界面
            if self.progress_callback:
                self.progress_callback(request_info)
            
        except Exception as e:
            print(f"处理WebSocket请求时出错: {str(e)}")
            print(f"Payload: {payload}")

    def _process_network_request(self, payload):
        """处理网络连接请求"""
        try:
            subtype = payload.get('subtype', '')
            
            # 处理不同类型的网络连接
            if subtype == 'socket_connect' or subtype == 'native_connect':
                host = payload.get('host', '') or payload.get('ip', '')
                port = payload.get('port', '')
            elif subtype == 'socket_address':
                host = payload.get('host', '')
                port = payload.get('port', '')
            else:
                # 其他类型的网络连接
                return
            
            if not host:
                print(f"警告: 无法获取网络连接主机信息 - payload: {payload}")
                return
            
            # 解析IP
            try:
                ip = socket.gethostbyname(host) if not self._is_ip(host) else host
            except:
                ip = "Unknown"
            
            # 生成唯一标识
            unique_id = f"net-{host}-{ip}-{port}-{subtype}"
            
            # 如果已经处理过该请求，则跳过
            if unique_id in self.request_set:
                return
            
            # 添加到已处理集合
            self.request_set.add(unique_id)
            
            # 获取IP信息
            ip_info = self._get_ip_info(ip) if ip != "Unknown" else {
                'country': 'Unknown',
                'region': 'Unknown',
                'city': 'Unknown',
                'isp': 'Unknown',
                'org': 'Unknown'
            }
            
            request_info = {
                'type': 'Network',
                'subtype': subtype,
                'domain': host if not self._is_ip(host) else "",
                'ip': ip,
                'port': str(port),
                'timestamp': payload.get('timestamp', datetime.now().isoformat()),
                'country': ip_info.get('country', 'Unknown'),
                'region': ip_info.get('region', 'Unknown'),
                'city': ip_info.get('city', 'Unknown'),
                'isp': ip_info.get('isp', 'Unknown'),
                'org': ip_info.get('org', 'Unknown')
            }
            
            # 添加到结果列表
            if not hasattr(self, 'results') or self.results is None:
                self.results = {'requests': []}
            self.results['requests'].append(request_info)
            
            # 回调更新界面
            if self.progress_callback:
                self.progress_callback(request_info)
            
        except Exception as e:
            print(f"处理网络连接请求时出错: {str(e)}")
            print(f"Payload: {payload}")

    def _is_ip(self, addr):
        """检查是否为IP地址"""
        import re
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        return bool(ip_pattern.match(addr)) 

    def set_progress_callback(self, callback):
        self.progress_callback = callback

    def push_frida_server(self):
        """手动推送并启动 frida-server"""
        try:
            print("\n开始推送 frida-server...")
            
            # 检查 frida-server 文件
            base_path = os.path.dirname(os.path.abspath(__file__))
            server_path = os.path.join(base_path, 'frida-server')
            if not os.path.exists(server_path):
                raise Exception("frida-server 文件不存在")
            
            # 先停止现有的 frida-server
            print("停止现有 frida-server...")
            try:
                subprocess.run([self.adb_path, 'shell', 'su -c "pkill -f frida-server"'], 
                             capture_output=True, timeout=5)
                time.sleep(2)
            except:
                pass
            
            # 删除设备上的旧文件
            print("删除旧文件...")
            try:
                subprocess.run([self.adb_path, 'shell', 'su -c "rm -f /data/local/tmp/frida-server"'],
                             capture_output=True, timeout=5)
                time.sleep(1)
            except:
                pass
            
            # 推送新文件
            print("推送新文件...")
            try:
                process = subprocess.Popen(
                    [self.adb_path, 'push', server_path, '/data/local/tmp/'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )
                
                stdout, stderr = process.communicate(timeout=30)
                if process.returncode != 0 or "error" in (stdout + stderr).lower():
                    raise Exception(f"推送失败: {stdout}\n{stderr}")
                    
            except Exception as e:
                raise Exception(f"推送文件失败: {str(e)}")
            
            # 验证文件是否存在
            print("验证文件...")
            try:
                check_result = subprocess.run([self.adb_path, 'shell', 'su -c "ls -l /data/local/tmp/frida-server"'],
                                        capture_output=True, text=True, timeout=5)
                if "No such file" in check_result.stdout or "No such file" in check_result.stderr:
                    raise Exception("文件未成功推送到设备")
            except Exception as e:
                raise Exception(f"文件验证失败: {str(e)}")
            
            # 设置权限
            print("设置权限...")
            try:
                # 设置执行权限
                subprocess.run([self.adb_path, 'shell', 'su -c "chmod 755 /data/local/tmp/frida-server"'],
                             capture_output=True, timeout=5, check=True)
                # 设置所有者
                subprocess.run([self.adb_path, 'shell', 'su -c "chown root:root /data/local/tmp/frida-server"'],
                             capture_output=True, timeout=5, check=True)
            except Exception as e:
                raise Exception(f"设置权限失败: {str(e)}")
            
            # 启动 frida-server
            print("\n启动 frida-server...")
            try:
                # 先尝试使用 setsid 启动
                start_cmd = 'su -c "cd /data/local/tmp && setsid ./frida-server &"'
                try:
                    subprocess.run([self.adb_path, 'shell', start_cmd],
                                 capture_output=True, timeout=10)  # 增加超时时间到10秒
                except subprocess.TimeoutExpired:
                    # 超时不一定意味着失败，继续检查进程
                    pass
                
                # 等待2秒让进程启动
                time.sleep(2)
                
                # 检查是否成功启动
                check_cmd = 'su -c "ps -ef | grep frida-server"'
                check_result = subprocess.run([self.adb_path, 'shell', check_cmd],
                                           capture_output=True, text=True, timeout=5)
                
                if 'frida-server' not in check_result.stdout:
                    print("第一次启动尝试失败，使用备选方法...")
                    
                    # 尝试使用 nohup 启动
                    start_cmd = 'su -c "cd /data/local/tmp && nohup ./frida-server > /dev/null 2>&1 &"'
                    try:
                        subprocess.run([self.adb_path, 'shell', start_cmd],
                                     capture_output=True, timeout=10)
                    except subprocess.TimeoutExpired:
                        pass
                    
                    time.sleep(2)
                    
                    # 再次检查
                    check_result = subprocess.run([self.adb_path, 'shell', check_cmd],
                                               capture_output=True, text=True, timeout=5)
                    
                    if 'frida-server' not in check_result.stdout:
                        print("第二次启动尝试失败，使用最后方法...")
                        
                        # 最后尝试
                        start_cmd = 'su -c "cd /data/local/tmp && ./frida-server &"'
                        try:
                            subprocess.run([self.adb_path, 'shell', start_cmd],
                                         capture_output=True, timeout=10)
                        except subprocess.TimeoutExpired:
                            pass
                
            except Exception as e:
                print(f"启动命令执行出错: {str(e)}")
                # 继续执行，让后续的验证来确定是否真的失败
            
            # 等待启动
            print("等待服务启动...")
            max_retries = 15
            for i in range(max_retries):
                if self.verify_frida_server():
                    print("frida-server 启动成功")
                    return True
                print(f"等待服务启动... ({i+1}/{max_retries})")
                time.sleep(2)
            
            raise Exception("frida-server 启动超时")
            
        except Exception as e:
            print(f"推送 frida-server 时出错: {str(e)}")
            return False

    def verify_frida_server(self):
        """验证 frida-server 是否正常运行"""
        try:
            print("\n验证 frida-server 状态...")
            
            # 检查进程
            print("检查进程...")
            try:
                ps_result = subprocess.run([self.adb_path, 'shell', 'ps | grep frida-server'],
                                        capture_output=True, text=True, timeout=5)
                if 'frida-server' not in ps_result.stdout:
                    print("frida-server 进程未运行")
                    return False
                print("frida-server 进程正在运行")
                return True
                
            except subprocess.CalledProcessError:
                print("frida-server 进程未运行")
                return False
            except Exception as e:
                print(f"检查进程失败: {str(e)}")
                return False
                
        except Exception as e:
            print(f"验证 frida-server 时出错: {str(e)}")
            return False

    def _auto_save_results(self):
        """自动保存当前结果"""
        try:
            if self.results and self.results.get('requests'):
                save_dir = os.path.join(os.path.dirname(self.results.get('file_name', '')), "网络分析结果")
                if not os.path.exists(save_dir):
                    os.makedirs(save_dir)
                
                # 添加自动保存标记
                self.results['auto_save'] = True
                
                # 使用 OutputHandler 保存结果
                from output_handler import OutputHandler
                output_handler = OutputHandler(save_dir)
                output_handler.save_results(self.results)
                
                # 更新保存时间
                self.last_save_time = datetime.now()
                
        except Exception as e:
            print(f"自动保存结果时出错: {str(e)}")

def main():
    try:
        # 创建分析器实例
        analyzer = ApkAnalyzer()
        
        # 设置夜神模拟器路径
        while True:
            nox_path = input("请输入夜神模拟器安装路径 (例如 C:/Program Files/Nox): ").strip()
            if analyzer.set_nox_path(nox_path):
                break
            print("请重新输入正确的路径")
        
        # 设置环境
        if not analyzer.setup_environment():
            print("环境设置失败，程序退出")
            return
        
        # 连接模拟器
        print("正在连接模拟器...")
        if not analyzer.connect_emulator():
            print("模拟器连接失败，程序退出")
            return
        
        while True:
            print("\n请选择操作：")
            print("1. 分析单个APK")
            print("2. 批量分析APK")
            print("3. 退出")
            
            choice = input("请输入选项 (1-3): ").strip()
            
            if choice == '1':
                apk_path = input("请输入APK文件路径: ").strip()
                if not os.path.exists(apk_path):
                    print("错误：文件不存在")
                    continue
                    
                print("开始分析APK...")
                results = analyzer.analyze_apk(apk_path)
                
                if results:
                    print("分析完成")
                
            elif choice == '2':
                folder_path = input("请输入APK文件夹路径: ").strip()
                if not os.path.exists(folder_path):
                    print("错误：文件夹不存在")
                    continue
                    
                for file in os.listdir(folder_path):
                    if file.endswith('.apk'):
                        print(f"\n正在分析: {file}")
                        results = analyzer.analyze_apk(os.path.join(folder_path, file))
                        
                print("批量分析完成")
                
            elif choice == '3':
                print("程序退出")
                break
                
            else:
                print("无效的选项，请重新选择")
                
    except KeyboardInterrupt:
        print("\n程序被用户中断")
    except Exception as e:
        print(f"程序运行出错: {str(e)}")

if __name__ == "__main__":
    main() 