@echo off
call "E:\VISUAL STUDIOO MICROSOFT\VC\Auxiliary\Build\vcvars32.bat"
where cl
where rc
where link
if not exist obj mkdir obj
cl /nologo /MT /O2 /wd4828 /D_USRDLL /D_WINDLL /I. /c /Foobj\ dllmain.cpp MinHook\buffer.cpp MinHook\hook.cpp MinHook\trampoline.cpp MinHook\hde\hde32.cpp
rc /nologo /foobj\resource.res resource.rc
link /nologo /DLL /OUT:snusik.dll obj\dllmain.obj obj\buffer.obj obj\hook.obj obj\trampoline.obj obj\hde32.obj obj\resource.res kernel32.lib user32.lib ws2_32.lib psapi.lib shell32.lib
echo Done
pause
