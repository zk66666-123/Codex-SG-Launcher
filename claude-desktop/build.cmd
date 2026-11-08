@echo off
setlocal EnableExtensions DisableDelayedExpansion
pushd "%~dp0" || exit /b 1
set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" goto :nocsc
"%CSC%" /nologo /target:winexe /platform:x64 /optimize+ /codepage:65001 /r:System.dll /r:System.Windows.Forms.dll /out:claude-desktop.exe tools\DesktopLauncher.cs
if errorlevel 1 goto :fail
where cl.exe >nul 2>nul && goto :compile
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto :nocl
set "VSROOT="
for /f "usebackq delims=" %%V in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSROOT=%%V"
if not defined VSROOT goto :nocl
call "%VSROOT%\Common7\Tools\VsDevCmd.bat" -no_logo -arch=x64 -host_arch=x64
if errorlevel 1 goto :fail
:compile
if /i not "%VSCMD_ARG_TGT_ARCH%"=="x64" goto :nocl
if not exist build mkdir build
cl.exe /nologo /EHsc /std:c++17 /utf-8 /MT /O2 /Fo"build\ClaudeNetworkGuard.obj" /Fe"tools\ClaudeNetworkGuard.exe" "tools\ClaudeNetworkGuard.cpp" /link /INCREMENTAL:NO
if errorlevel 1 goto :fail
echo Built claude-desktop.exe and tools\ClaudeNetworkGuard.exe.
popd
exit /b 0
:nocsc
echo Missing .NET Framework 4.x x64 C# compiler. 1>&2
goto :fail
:nocl
echo Use x64 Native Tools Command Prompt with MSVC and Windows SDK installed. 1>&2
:fail
popd
exit /b 1
