@echo off

:: Check for Python and pip installation
python3 --version
if %errorlevel% neq 0 (
	echo Python is not installed or not found in PATH. Please install Python and add it to the PATH.
	exit /b
)

:: Install the cryptography library
echo Installing cryptography library...
python3 -m pip install cryptography

:: Verify the installation
python3 -c "import cryptography; print('Cryptography library version:', cryptography.__version__)"
if %errorlevel% neq 0 (
	echo Failed to install cryptography library.
	exit /b
)

echo All dependencies installed successfully.
pause