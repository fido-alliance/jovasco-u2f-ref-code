@echo OFF

::
::  This script extract the Windows Kit path from the registry.
::

setlocal ENABLEEXTENSIONS
set KEY_NAME="HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Kits\Installed Roots"
set VALUE_NAME=KitsRoot10

FOR /F "usebackq skip=2 tokens=1-2*" %%A IN (`REG QUERY %KEY_NAME% /v %VALUE_NAME% 2^>nul`) DO (
    set ValueName=%%A
    set ValueType=%%B
    set ValueValue=%%C
)

@echo WINDOWS_SDK = %ValueValue:\=/%
set found=0
IF EXIST "%ValueValue%UnionMetaData\Windows.winmd"  (
	set RefPath=-AI"%ValueValue:\=/%References/"
	set UMDPath=-AI"%ValueValue:\=/%UnionMetaData/"
	set found=1
) ELSE (
	FOR /F "usebackq skip=1 tokens=6 delims=\" %%A IN (`REG QUERY %KEY_NAME% /f "10.*" /k 2^>nul`) DO (
		IF %found% == 0 IF EXIST "%ValueValue%UnionMetaData\%%A\Windows.winmd" (
			set RefPath=-AI"%ValueValue:\=/%References/%%A"
			set UMDPath=-AI"%ValueValue:\=/%UnionMetaData/%%A"
			set found=1
		)
	)
)
if found==0 exit /b 0

@echo WINDOWS_SDK_PATHS = $(WINDOWS_SDK_PATHS) %RefPath% %UMDPath%
exit /b 1