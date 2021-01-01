dotnet nuget push "src\WindowsHello\bin\Release\HaemmerElectronics.SeppPenner.WindowsHello.*.nupkg" -s "github" --skip-duplicate
dotnet nuget push "src\WindowsHello\bin\Release\HaemmerElectronics.SeppPenner.WindowsHello.*.nupkg" -s "nuget.org" --skip-duplicate -k "%NUGET_API_KEY%"
PAUSE