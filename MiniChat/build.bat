@echo off
rem Builds MiniChat.exe with the C# compiler that comes with Windows (.NET Framework 4).
cd /d "%~dp0"
"%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /codepage:65001 /optimize /target:winexe /out:MiniChat.exe /r:System.Web.Extensions.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll MiniChat.cs
if %errorlevel%==0 (echo Built MiniChat.exe) else (echo Build failed)
