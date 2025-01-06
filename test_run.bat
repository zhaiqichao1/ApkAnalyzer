@echo off
chcp 65001

cd dist\APK网络分析工具
echo 正在测试运行程序...
APK网络分析工具.exe
if errorlevel 1 (
    echo 程序运行失败！
    cd ..\..
    pause
    exit /b 1
)
cd ..\..
echo 测试运行成功！
pause 