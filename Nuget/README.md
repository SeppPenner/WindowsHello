WindowsHello
====================================

WindowsHello is an assembly/ library to work with [Microsoft's Windows Hello](https://support.microsoft.com/de-de/help/17215/windows-10-what-is-hello) in aplications.
The assembly was written and tested in .Net 4.8.

[![Build status](https://ci.appveyor.com/api/projects/status/a8h66id7bqk07n79?svg=true)](https://ci.appveyor.com/project/SeppPenner/windowshello)
[![GitHub issues](https://img.shields.io/github/issues/SeppPenner/WindowsHello.svg)](https://github.com/SeppPenner/WindowsHello/issues)
[![GitHub forks](https://img.shields.io/github/forks/SeppPenner/WindowsHello.svg)](https://github.com/SeppPenner/WindowsHello/network)
[![GitHub stars](https://img.shields.io/github/stars/SeppPenner/WindowsHello.svg)](https://github.com/SeppPenner/WindowsHello/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://raw.githubusercontent.com/SeppPenner/WindowsHello/master/License.txt)
[![Nuget](https://img.shields.io/badge/WindowsHello-Nuget-brightgreen.svg)](https://www.nuget.org/packages/HaemmerElectronics.SeppPenner.WindowsHello/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/HaemmerElectronics.SeppPenner.WindowsHello.svg)](https://www.nuget.org/packages/HaemmerElectronics.SeppPenner.WindowsHello/)
[![Known Vulnerabilities](https://snyk.io/test/github/SeppPenner/WindowsHello/badge.svg)](https://snyk.io/test/github/SeppPenner/WindowsHello)
[![Gitter](https://badges.gitter.im/WindowsHello2/community.svg)](https://gitter.im/WindowsHello2/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

## Available for
* NetFramework 4.6
* NetFramework 4.6.2
* NetFramework 4.7
* NetFramework 4.7.2
* NetFramework 4.8

## Net Framework latest and LTS versions
* https://dotnet.microsoft.com/download/dotnet-framework

## Basic usage (Version 1.0.4.0 and above):
```csharp
public void WindowsHelloTest()
{
    var handle = new IntPtr();
    var data = new byte[] { 0x32, 0x32 };
    var provider = WinHelloProvider.CreateInstance("Hello", handle);
    // Set the persistent key name if you want:
    provider.SetPersistentKeyName("Test");
    var encryptedData = provider.Encrypt(data);
    var decryptedData = provider.PromptToDecrypt(encryptedData);
}
```

## Basic usage (Before version 1.0.4.0):
```csharp
public void WindowsHelloTest()
{
    var handle = new IntPtr();
    var data = new byte[] { 0x32, 0x32 };
    IAuthProvider provider = new WinHelloProvider("Hello", handle);
    var encryptedData = provider.Encrypt(data);
    var decryptedData = provider.PromptToDecrypt(encryptedData);
}
```

The project can be found on [nuget](https://www.nuget.org/packages/HaemmerElectronics.SeppPenner.WindowsHello/).

## Further links
This project is mainly taken from https://github.com/sirAndros/KeePassWinHello.

Change history
--------------

* **Version 1.0.5.0 (2020-05-10)** : Updated nuget packages.
* **Version 1.0.4.0 (2019-11-18)** : Fixed security bug (Thanks to [@Angelelz](https://github.com/Angelelz)).
* **Version 1.0.3.0 (2019-11-08)** : Updated nuget packages.
* **Version 1.0.2.0 (2019-06-23)** : Added icon to the nuget package.
* **Version 1.0.0.1 (2019-05-05)** : Updated .Net version to 4.8.
* **Version 1.0.0.0 (2019-02-09)** : 1.0 release.
