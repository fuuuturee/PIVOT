@echo off
rem ---------------------------------------------------------------- PIVOT build
rem Usage: build.bat [debug|release]
rem
rem Uses the MSVC environment that is already active (for example on GitHub
rem Actions) and sets it up itself when it is not.
setlocal enabledelayedexpansion

set "MODE=%~1"
if "%MODE%"=="" set "MODE=release"

where cl >nul 2>&1
if errorlevel 1 (
  set "VSWHERE=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
  if not exist "!VSWHERE!" (
    for /d %%D in ("C:\Program Files\Microsoft Visual Studio\*") do (
      if exist "%%~fD\VC\Auxiliary\Build\vcvars64.bat" set "VSWHERE=%%~fD\VC\Auxiliary\Build\vcvars64.bat"
    )
  )
  if not exist "!VSWHERE!" (
    for /d %%D in ("C:\Program Files (x86)\Microsoft Visual Studio\*") do (
      if exist "%%~fD\VC\Auxiliary\Build\vcvars64.bat" set "VSWHERE=%%~fD\VC\Auxiliary\Build\vcvars64.bat"
    )
  )
  if not exist "!VSWHERE!" (
    echo [build] vcvars64.bat not found - install Visual Studio with the C++ workload
    exit /b 1
  )
  echo [build] setting up the MSVC environment from "!VSWHERE!"
  call "!VSWHERE!" >nul
)

rem The compiler decides whether the environment is usable - vcvars can report
rem a non zero error level even when everything is fine.
where cl >nul 2>&1
if errorlevel 1 (
  echo [build] the MSVC compiler is not available
  exit /b 1
)

cd /d "%~dp0"

if /i "%MODE%"=="debug" (
  rem /MDd is required: _DEBUG pulls in the debug CRT symbols
  set "OPT=/Od /Zi /D_DEBUG /MDd"
  set "OUT=bin\debug"
) else (
  rem static CRT so the released binary runs on any Windows 10+ without
  redistributables
  set "OPT=/O2 /DNDEBUG /Zi /MT"
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
"%OUT%\pivot.exe" --version
endlocal
