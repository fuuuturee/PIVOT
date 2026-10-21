@echo off
rem ---------------------------------------------------------------- PIVOT build
rem Usage: build.bat [debug|release]
setlocal

set "MODE=%~1"
if "%MODE%"=="" set "MODE=release"

set "VSWHERE=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VSWHERE%" (
  for /d %%D in ("C:\Program Files\Microsoft Visual Studio\*") do (
    if exist "%%~fD\VC\Auxiliary\Build\vcvars64.bat" set "VSWHERE=%%~fD\VC\Auxiliary\Build\vcvars64.bat"
  )
)
if not exist "%VSWHERE%" (
  echo [build] vcvars64.bat not found - install Visual Studio with C++ workload
  exit /b 1
)

call "%VSWHERE%" >nul
if errorlevel 1 (
  echo [build] vcvars64 failed
  exit /b 1
)

cd /d "%~dp0"

if /i "%MODE%"=="debug" (
  set "OPT=/Od /Zi /D_DEBUG"
  set "OUT=bin\debug"
) else (
  set "OPT=/O2 /DNDEBUG /Zi"
  set "OUT=bin\release"
)

if not exist "%OUT%" mkdir "%OUT%"
if not exist "obj" mkdir "obj"

echo [build] mode=%MODE% -^> %OUT%
cl /nologo /std:c++20 /EHsc /W3 /D_CRT_SECURE_NO_WARNINGS %OPT% /I src ^
   /Fo:obj\ /Fd:obj\vc140.pdb /Fe:"%OUT%\pivot.exe" ^
   src\main.cpp src\record.cpp src\util.cpp src\index.cpp ^
   src\parsers\prefetch.cpp src\parsers\lnk.cpp src\parsers\pe.cpp ^
   /link /incremental:no /PDB:"obj\vc140.pdb"

if errorlevel 1 (
  echo [build] FAILED
  exit /b 1
)
echo [build] ok -^> %OUT%\pivot.exe
endlocal
