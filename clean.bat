@echo off
echo 正在清理旧的构建文件...

:: 结束可能正在运行的进程
taskkill /F /IM "APK网络分析工具.exe" 2>nul
taskkill /F /IM "python.exe" 2>nul

:: 等待进程完全结束
timeout /t 2 /nobreak >nul

:: 删除构建目录
rmdir /s /q build 2>nul
rmdir /s /q dist 2>nul

:: 删除临时文件
del /f /q *.spec 2>nul
del /f /q *.pyc 2>nul

echo 清理完成！
timeout /t 2 >nul 