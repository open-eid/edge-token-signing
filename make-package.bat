@Echo Off

Echo Building solution
msbuild /nologo /verbosity:quiet /p:Configuration=Release;Platform=x86 TokenSigning.sln

Echo Copying Appx source files
MD Package
cd Package
DEL /Q Appx\*.*
MD AppX
DEL TokenSigning.Appx
DEL priconfig.xml
Copy ..\TokenSigning\bin\x86\Release\AppxManifest.xml AppX\AppxManifest.xml
Copy ..\HostBackend\bin\Release\HostBackend.exe AppX\HostBackend.exe
Copy ..\TokenSigning\bin\x86\Release\TokenSigning.exe AppX\TokenSigning.exe
MD Appx\Assets
Copy ..\TokenSigning\Assets\*.* Appx\Assets
MD Appx\Extension
Copy ..\TokenSigning\Extension\*.* Appx\Extension

Echo MakePri
cd AppX
makepri createconfig /cf ..\priconfig.xml /pv 10.0 /dq en-US
makepri new /pr . /cf ..\priconfig.xml /of ..\resources.pri /mf AppX /o

Echo Making Appx
makeappx pack /l /m AppXManifest.xml /f ..\resources.map.txt /p ..\TokenSigning.Appx /o
cd ..

Echo Signing the package
Signtool.exe sign /a /v /fd SHA256 /f ..\TokenSigning\TokenSigning_TemporaryKey.pfx TokenSigning.appx

cd ..
