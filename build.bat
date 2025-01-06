@echo off
chcp 65001

:: 先运行清理脚本
call clean.bat

:: 检查 Python 安装
echo 正在检查Python环境...
where python >nul 2>&1
if errorlevel 1 (
    :: 尝试查找 Python 安装路径
    set PYTHON_PATHS=^
        "C:\Python39\python.exe" ^
        "C:\Python38\python.exe" ^
        "%LOCALAPPDATA%\Programs\Python\Python39\python.exe" ^
        "%LOCALAPPDATA%\Programs\Python\Python38\python.exe" ^
        "%PROGRAMFILES%\Python39\python.exe" ^
        "%PROGRAMFILES%\Python38\python.exe" ^
        "%PROGRAMFILES(X86)%\Python39\python.exe" ^
        "%PROGRAMFILES(X86)%\Python38\python.exe"

    for %%i in (%PYTHON_PATHS%) do (
        if exist %%i (
            set PYTHON_PATH=%%i
            goto :found_python
        )
    )
    
    echo Python未找到！请确保已安装Python 3.8或更高版本，并已添加到环境变量。
    echo 可能的解决方法：
    echo 1. 重新安装Python，安装时勾选"Add Python to PATH"
    echo 2. 手动将Python添加到环境变量
    echo 3. 或直接输入Python安装路径：
    set /p PYTHON_PATH="请输入Python.exe的完整路径: "
    if not exist "%PYTHON_PATH%" (
        echo 输入的路径不存在！
        pause
        exit /b 1
    )
)

:found_python
if defined PYTHON_PATH (
    echo 使用Python路径: %PYTHON_PATH%
    set PYTHON_CMD="%PYTHON_PATH%"
) else (
    set PYTHON_CMD=python
)

:: 检查Python版本
%PYTHON_CMD% -c "import sys; v=sys.version_info; exit(1 if v.major != 3 or v.minor < 8 else 0)"
if errorlevel 1 (
    echo 需要Python 3.8或更高版本！
    echo 当前Python版本:
    %PYTHON_CMD% --version
    pause
    exit /b 1
)

:: 检查tkinter
%PYTHON_CMD% -c "import tkinter" >nul 2>&1
if errorlevel 1 (
    echo tkinter未安装！
    echo 请按照以下步骤安装tkinter:
    echo 1. 卸载当前的Python
    echo 2. 重新安装Python，安装时勾选"tcl/tk and IDLE"选项
    pause
    exit /b 1
)

echo 正在安装/更新依赖...
%PYTHON_CMD% -m pip install --upgrade pip
%PYTHON_CMD% -m pip install -r requirements.txt
if errorlevel 1 (
    echo 安装依赖失败！
    pause
    exit /b 1
)

echo 正在创建必要目录...
if not exist scripts mkdir scripts
if not exist output mkdir output

echo 正在复制必要文件...
if not exist "scripts\network_monitor.js" (
    echo console.log("Monitoring network..."); > "scripts\network_monitor.js"
)
if not exist "config.json" (
    echo { "nox_path": "", "output_dir": "output" } > "config.json"
)
if not exist "analysis.db" (
    copy nul "analysis.db"
)

echo 正在打包应用程序...
%PYTHON_CMD% -m PyInstaller --clean build.spec
if errorlevel 1 (
    echo 打包失败！
    pause
    exit /b 1
)

echo 正在复制额外文件到打包目录...
xcopy /y /i "config.json" "dist\APK网络分析工具\" >nul
xcopy /y /i "analysis.db" "dist\APK网络分析工具\" >nul
xcopy /y /i /e "scripts" "dist\APK网络分析工具\scripts\" >nul
if exist "frida-server" xcopy /y /i "frida-server" "dist\APK网络分析工具\" >nul

echo 正在验证打包结果...
if not exist "dist\APK网络分析工具\APK网络分析工具.exe" (
    echo 打包后的可执行文件不存在！
    pause
    exit /b 1
)

echo 打包完成！
echo 程序位置: dist\APK网络分析工具\APK网络分析工具.exe
pause 