@echo off
chcp 65001

echo 正在创建虚拟环境...
python -m venv venv

echo 激活虚拟环境...
call venv\Scripts\activate

echo 安装依赖...
pip install --upgrade pip
pip install -r requirements.txt

echo 创建必要目录...
if not exist scripts mkdir scripts
if not exist output mkdir output

echo 创建基础配置文件...
if not exist "config.json" (
    echo { "nox_path": "", "last_apk_path": "" } > "config.json"
)

if not exist "analysis.db" (
    copy nul "analysis.db"
)

echo 环境准备完成！
pause 