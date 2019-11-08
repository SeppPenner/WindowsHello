dotnet build WindowsHello.sln -c Release
xcopy /s .\WindowsHello\bin\Release ..\Nuget\Source\
pause