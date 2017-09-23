@echo off

rem Tested on clean Windows10 VM with erl9.0/OTP20/Elixir1.4.5
rem Visual C++ 2015 Build Tools
rem Microsoft Visual C++ Build Tools 14.0.25420.1
rem visualcppbuildtools_full.exe (Default Package Selection)
call "C:\Program Files (x86)\Microsoft Visual C++ Build Tools\vcbuildtools.bat" amd64

rem If NMAKE is not found chances are that your build tools have been messed up
rem It happened to me after installing Visual Studio Pro 2017
rem Repairing the build tools install did not help
rem Uncomment PATH set below for a quick fix if NMAKE is not found
rem set PATH=%PATH%;C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\bin

rem Erlang INCLUDE folder path is passed unquoted from mix
rem C:\Program Files\erlX.Y\erts-X.Y\include
set INCLUDE=%*;%INCLUDE%
rem echo %INCLUDE%
cd %~dp0

if not exist obj mkdir obj
if not exist priv mkdir priv
call nmake /F make.winnt
