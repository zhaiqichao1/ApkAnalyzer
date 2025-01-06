@echo off
echo 开始构建流程...

echo 1. 激活虚拟环境
call venv\Scripts\activate

echo 2. 更新依赖
pip install -r requirements.txt

echo 3. 开始打包
call build.bat

echo 构建流程完成！
pause 