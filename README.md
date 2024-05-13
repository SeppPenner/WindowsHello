WindowsHello
====================================

WindowsHello is an assembly/ library to work with [Microsoft's Windows Hello](https://support.microsoft.com/de-de/help/17215/windows-10-what-is-hello) in aplications.

[![Build status](https://ci.appveyor.com/api/projects/status/a8h66id7bqk07n79?svg=true)](https://ci.appveyor.com/project/SeppPenner/windowshello)
[![GitHub issues](https://img.shields.io/github/issues/SeppPenner/WindowsHello.svg)](https://github.com/SeppPenner/WindowsHello/issues)
[![GitHub forks](https://img.shields.io/github/forks/SeppPenner/WindowsHello.svg)](https://github.com/SeppPenner/WindowsHello/network)
[![GitHub stars](https://img.shields.io/github/stars/SeppPenner/WindowsHello.svg)](https://github.com/SeppPenner/WindowsHello/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://raw.githubusercontent.com/SeppPenner/WindowsHello/master/License.txt)
[![Nuget](https://img.shields.io/badge/WindowsHello-Nuget-brightgreen.svg)](https://www.nuget.org/packages/HaemmerElectronics.SeppPenner.WindowsHello/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/HaemmerElectronics.SeppPenner.WindowsHello.svg)](https://www.nuget.org/packages/HaemmerElectronics.SeppPenner.WindowsHello/)
[![Known Vulnerabilities](https://snyk.io/test/github/SeppPenner/WindowsHello/badge.svg)](https://snyk.io/test/github/SeppPenner/WindowsHello)
[![Gitter](https://badges.gitter.im/WindowsHello2/community.svg)](https://gitter.im/WindowsHello2/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)
[![Blogger](https://img.shields.io/badge/Follow_me_on-blogger-orange)](https://franzhuber23.blogspot.de/)
[![Patreon](https://img.shields.io/badge/Patreon-F96854?logo=patreon&logoColor=white)](https://patreon.com/SeppPennerOpenSourceDevelopment)
[![PayPal](https://img.shields.io/badge/PayPal-00457C?logo=paypal&logoColor=white)](https://paypal.me/th070795)

<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-2-orange.svg?style=flat-square)](#contributors-)
<!-- ALL-CONTRIBUTORS-BADGE:END -->

## Available for
* Net 6.0
* Net 8.0

## Net Framework latest and LTS versions
* https://dotnet.microsoft.com/download/dotnet

## Basic usage (Version 1.0.4.0 and above)
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

## Basic usage (Before version 1.0.4.0)
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

## Install

```bash
dotnet add package HaemmerElectronics.SeppPenner.WindowsHello
```

## Further links
This project is mainly taken from https://github.com/sirAndros/KeePassWinHello.

Change history
--------------

See the [Changelog](https://github.com/SeppPenner/WindowsHello/blob/master/Changelog.md).

## Contributors ✨

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/danergo"><img src="https://avatars.githubusercontent.com/u/11708344?v=4?s=100" width="100px;" alt="danergo"/><br /><sub><b>danergo</b></sub></a><br /><a href="https://github.com/SeppPenner/WindowsHello/commits?author=danergo" title="Tests">⚠️</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://franzhuber23.blogspot.de/"><img src="https://avatars.githubusercontent.com/u/9639361?v=4?s=100" width="100px;" alt="HansM"/><br /><sub><b>HansM</b></sub></a><br /><a href="https://github.com/SeppPenner/WindowsHello/commits?author=SeppPenner" title="Code">💻</a> <a href="https://github.com/SeppPenner/WindowsHello/commits?author=SeppPenner" title="Documentation">📖</a> <a href="#example-SeppPenner" title="Examples">💡</a> <a href="#maintenance-SeppPenner" title="Maintenance">🚧</a> <a href="#projectManagement-SeppPenner" title="Project Management">📆</a> <a href="https://github.com/SeppPenner/WindowsHello/commits?author=SeppPenner" title="Tests">⚠️</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!