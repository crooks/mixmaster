set VERSION=204
set INST=[drive & full path to \build directory created by unzipping DOS source]
set DEST=[drive & full path of directory to put OS/2 executable after compilation]
set SRC=[drive & full path to \src directory created by unzipping DOS source]
set GNU=[drive & full path of EMX for OS/2 directory]

set DJDIR=%GNU%
set PATH=%PATH%;[add drive and full path in GNU setting above] 

set USER=os2user
set TMPDIR=%DJDIR%/tmp
set GO32TMP=%DJDIR%/tmp
set C_INCLUDE_PATH=%/>;C_INCLUDE_PATH%%DJDIR%/include
set COMPILER_PATH=%/>;COMPILER_PATH%%DJDIR%/bin
set LIBRARY_PATH=%/>;LIBRARY_PATH%%DJDIR%/lib

cd %SRC%\rsaref\install\unix
gmake rsaref.a CC=gcc LIB=ar RANLIB="ar -s"
cd %SRC%\zlib
gmake libz.a
cd %SRC%
gmake mixmaster MIXPATH=.  PASS=""
if not exist mixmaster goto :end
emxbind -o %DEST%\mixmaster.exe mixmaster
cd %DEST%
:end
