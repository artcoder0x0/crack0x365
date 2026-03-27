@echo off
setlocal EnableDelayedExpansion

:: Store the root directory where the script is run
set "ROOT_DIR=%CD%"
:: Initialize output file in the root directory
echo Directory structure for %ROOT_DIR% > "%ROOT_DIR%\project-directory-map.txt"
echo. >> "%ROOT_DIR%\project-directory-map.txt"

:: Call the recursive directory processing function
call :processDir "%CD%"

echo Done! Directory map created in project-directory-map.txt
exit /b

:processDir
set "currentDir=%~1"
pushd "%currentDir%"

:: List contents of current directory and append to the root directory's output file
echo. >> "%ROOT_DIR%\project-directory-map.txt"
echo Directory: %currentDir% >> "%ROOT_DIR%\project-directory-map.txt"
echo ----------------------------------- >> "%ROOT_DIR%\project-directory-map.txt"
dir /b >> "%ROOT_DIR%\project-directory-map.txt"
echo. >> "%ROOT_DIR%\project-directory-map.txt"

:: Process subdirectories, excluding node_modules
for /d %%D in (*) do (
    if /I not "%%D"=="node_modules" (
        call :processDir "%currentDir%\%%D"
    )
)

popd
exit /b
