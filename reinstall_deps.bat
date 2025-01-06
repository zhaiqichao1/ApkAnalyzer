@echo off
chcp 65001

echo 删除旧的虚拟环境...
rmdir /s /q venv

echo 创建新的虚拟环境...
python -m venv venv

echo 激活虚拟环境...
call venv\Scripts\activate

echo 升级pip...
python -m pip install --upgrade pip

echo 安装依赖...
pip install pyinstaller openpyxl pillow requests frida frida-tools colorama

echo 完成！
pause 