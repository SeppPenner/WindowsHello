cd .\src

@ECHO off
cls

FOR /d /r . %%d in (bin,obj) DO (
	IF EXIST "%%d" (		 	 
		ECHO %%d | FIND /I "\node_modules\" > Nul && ( 
			ECHO.Skipping: %%d
		) || (
			ECHO.Deleting: %%d
			rd /s/q "%%d"
		)
	)
)

@ECHO.Building solution...
@dotnet restore
@dotnet build -c Release
@cd .\WindowsHello\bin\Release
@ECHO.Build successful.
@REM Keep echo off and the @ on every push line. With echo on, cmd writes the command
@REM line to the console after expanding the variables, which prints both API keys
@REM in clear text.
@dotnet nuget push *.nupkg -s "nuget.org" --skip-duplicate -k "%NUGET_API_KEY%"
@dotnet nuget push *.snupkg -s "nuget.org" --skip-duplicate -k "%NUGET_API_KEY%"
@dotnet nuget push *.nupkg -s "github" --skip-duplicate --api-key "%GITHUB_API_KEY%"
@dotnet nuget push *.snupkg -s "github" --skip-duplicate --api-key "%GITHUB_API_KEY%"
@ECHO.Upload success. Press any key to exit.
PAUSE