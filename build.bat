@echo off
rem ---------------------------------------------------------------- PIVOT build
rem Usage: build.bat [debug|release]
rem
rem Builds two executables:
rem   pivot.exe      command line client
rem   pivot-gui.exe  native Windows GUI
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
  rem redistributables
  set "OPT=/O2 /DNDEBUG /Zi /MT"
  set "OUT=bin\release"
)

if not exist "%OUT%" mkdir "%OUT%"
if not exist "obj\cli" mkdir "obj\cli"
if not exist "obj\gui" mkdir "obj\gui"

set "COMMON=src\engine.cpp src\record.cpp src\util.cpp src\index.cpp"
set "PARSERS=src\parsers\prefetch.cpp src\parsers\lnk.cpp src\parsers\pe.cpp"

echo [build] mode=%MODE% -^> %OUT%

rem ---------------------------------------------------------------- CLI
cl /nologo /std:c++20 /EHsc /W3 /D_CRT_SECURE_NO_WARNINGS %OPT% /I src ^
   /Fo:obj\cli\ /Fd:obj\cli\pivot.pdb /Fe:"%OUT%\pivot.exe" ^
   src\main.cpp %COMMON% %PARSERS% ^
   /link /incremental:no /PDB:"obj\cli\pivot.pdb"

if errorlevel 1 (
  echo [build] FAILED - cli
  exit /b 1
)

rem ---------------------------------------------------------------- GUI
rem /MANIFESTINPUT pulls in the visual styles and dpi awareness, /MANIFEST:EMBED
rem puts it into the binary instead of writing a sidecar file.
cl /nologo /std:c++20 /EHsc /W3 /D_CRT_SECURE_NO_WARNINGS /DUNICODE /D_UNICODE %OPT% /I src ^
   /Fo:obj\gui\ /Fd:obj\gui\pivot-gui.pdb /Fe:"%OUT%\pivot-gui.exe" ^
   src\gui\gui.cpp %COMMON% %PARSERS% ^
   /link /incremental:no /PDB:"obj\gui\pivot-gui.pdb" ^
   /SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup ^
   /MANIFEST:EMBED /MANIFESTUAC:NO /MANIFESTINPUT:"src\gui\pivot-gui.manifest" ^
    comctl32.lib user32.lib gdi32.lib advapi32.lib ole32.lib shell32.lib uuid.lib dwmapi.lib uxtheme.lib

if errorlevel 1 (
  echo [build] FAILED - gui
  exit /b 1
)

echo [build] ok -^> %OUT%\pivot.exe and %OUT%\pivot-gui.exe
"%OUT%\pivot.exe" --version
endlocal
