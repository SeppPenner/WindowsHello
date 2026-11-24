# Project rules for Claude

## What this is

WindowsHello is a class library that lets an application encrypt and decrypt data with a key that
Windows Hello protects. Encryption is silent, decryption triggers the Hello gesture (face,
fingerprint or PIN). The implementation talks to `ncrypt.dll` and the undocumented `cryptngc.dll`
through P/Invoke and stores an RSA 2048 key in the "Microsoft Passport Key Storage Provider". The
code is mainly taken from [KeePassWinHello](https://github.com/sirAndros/KeePassWinHello).

The repository **is** published as a NuGet package: `HaemmerElectronics.SeppPenner.WindowsHello`,
with `GeneratePackageOnBuild`, a symbol package (`snupkg`) and `BuildAndPushPackage.bat` for the
push. There is no installer and no application, the demo lives in the Readme.

One solution `src/WindowsHello.sln` with exactly two projects:

- `src/WindowsHello/WindowsHello.csproj`, the library. Multi-targets `net10.0-windows` and
  `net11.0-windows`, `UseWindowsForms` enabled.
- `src/WindowsHello.Tests/WindowsHello.Tests.csproj`, MSTest, `net11.0-windows`, `IsPackable`
  false.

Layout inside `src/WindowsHello`:

- `IAuthProvider.cs`: the public contract, three members. `PromptToDecrypt`, `Encrypt` and
  `SetPersistentKeyName`.
- `WinHelloProvider.cs`: the only implementation and the only file with logic, around 820 lines.
  Public surface: the static factory `CreateInstance(string message, IntPtr windowHandle)` plus the
  three interface members. Everything else is private: the `[DllImport]` declarations for
  `NCrypt*`, `NgcGetDefaultDecryptionKeyName`, the helpers `CreatePersistentKey`,
  `DeletePersistentKey`, `TryOpenPersistentKey`, `VerifyPersistentKeyIntegrity`, `ApplyUiContext`,
  `IsAvailable`, `RetrieveLocalKeyName`, `RetrievePersistentKeyName`, and the nested struct
  `SECURITY_STATUS` whose `CheckStatus` turns a negative status into an exception. The same file
  ends with the `internal sealed class AuthProviderUiContext`, which is the only reason the project
  needs WinForms: it implements `IWin32Window`.
- `Exceptions/`: seven exception types in one hierarchy. `WindowsHelloException` derives from
  `Exception`, `AuthProviderException` and `EnvironmentErrorException` from that,
  `AuthProviderInvalidKeyException`, `AuthProviderIsUnavailableException` and
  `AuthProviderUserCancelledException` from `AuthProviderException`, and
  `AuthProviderSystemErrorException` from `EnvironmentErrorException`. Only
  `EnvironmentErrorException` has the `(string message, int errorCode)` constructor that appends
  `"\nError code: " + errorCode.ToString("X")` to the message.
- `GlobalUsings.cs`: all usings of the project.

Layout inside `src/WindowsHello.Tests`:

- `TestWindowsHello.cs`: two test methods, `WindowsHelloTest` with the default key name and
  `WindowsHelloTest2` with `SetPersistentKeyName("Test")`. Both encrypt `{ 0x32, 0x32 }`, decrypt
  it again and compare. They are **not** unit tests, see "Known quirks".
- `GlobalUsings.cs`: the single using of the test project.

Repository root: `README.md` (the only user documentation, with the usage sample and the
contributors table), `Changelog.md`, `Updating.md` (five short release lines, the complete process
is under `## Releasing` below), `License.txt` (MIT), `Icon.png` (the package icon),
`BuildAndPushPackage.bat`, `Delete-BIN-OBJ-Folders.bat`,
`.all-contributorsrc`, `.gitattributes` and `.gitignore`. There is no `.github` folder, no
`HowToUse.md` and no screenshots.

## Build

```powershell
dotnet build src/WindowsHello.sln -c Release
```

```powershell
dotnet test src/WindowsHello.sln
```

- The library multi-targets `net10.0-windows` and `net11.0-windows`, the test project builds for
  `net11.0-windows` only. `RuntimeIdentifiers` is `win-x64`. The repository follows the sibling
  repositories in keeping the LTS framework plus the newest one, so a new .NET replaces the
  middle entry instead of being appended.
- All build properties live directly in the two `.csproj` files. `src/Directory.Build.props` exists
  but sets nothing except `GenerateDocumentationFile`, which is why every type and member needs an
  XML doc comment.
- `TreatWarningsAsErrors` is enabled in both projects, so every warning breaks the build, NuGet
  warnings (`NU****`) from restore included. A clean build reports zero warnings, keep it that way.
- `NU1803` (HTTP source usage during restore) is the one warning suppressed via `NoWarn`. Fix
  warnings instead of extending that list. `NuGetAudit` and `NuGetAuditMode=all` are on, so a
  vulnerable transitive package fails the build too.
- Versions come from GitVersion.MsBuild out of the git tags, for example `1.1.6-1` for the first
  commit after tag `1.1.5`. Never edit an assembly version by hand. The one version string that
  **is** maintained by hand is `PackageReleaseNotes` in `WindowsHello.csproj`, see "Releasing".
- Restore needs nuget.org. If a private feed is configured globally on the machine and answers 404
  for public packages, restore fails with `NU1301`. Then build with an explicit source:
  `dotnet build src/WindowsHello.sln --source https://api.nuget.org/v3/index.json`.
- Building needs the .NET 11 SDK, it builds the `net10.0-windows` target as well. `net8.0-windows`
  was dropped after version 1.1.5.0. Keep the test project on the newest framework the library
  targets.
- The test project uses the same package set as the sibling repositories:
  `Microsoft.NET.Test.Sdk`, `MSTest.TestAdapter`, `MSTest.TestFramework`, `coverlet.collector` and
  `GitVersion.MsBuild`.
- `Delete-BIN-OBJ-Folders.bat` removes every `bin` and `obj` below the repository root. Useful
  because `GeneratePackageOnBuild` leaves old `.nupkg` files behind, see "Known quirks".

## Code conventions

Follow the surrounding code, it is consistent throughout every file:

- File header comment block with `<copyright file="..." company="Hämmer Electronics">` and a
  `<summary>`, then the file-scoped namespace.
- XML doc comments on every type and every member, private members and the `[DllImport]`
  declarations included, no exceptions. `GenerateDocumentationFile` plus `TreatWarningsAsErrors`
  turns a missing comment into a build error (`CS1591`).
- `Nullable`, `ImplicitUsings` and `LangVersion latest` are enabled.
- New `using` directives go into the `GlobalUsings.cs` of the respective project, inside the
  existing `#pragma warning disable IDE0065` block, never at the top of a file. The editorconfig
  requires usings inside the namespace (`csharp_using_directive_placement=inside_namespace:warning`),
  which global usings cannot satisfy, that is what the pragma is for. Do not add other pragmas. The
  comment text in that block is German because Visual Studio generated it, leave it alone.
- Fields, properties, methods and events are always accessed with `this.` qualification
  (`dotnet_style_qualification_for_*` at severity `warning`). Note that most of the state in
  `WinHelloProvider` is static, so `this.` does not appear there, which is not a style violation.
- The P/Invoke declarations keep the native names and casing (`NCryptOpenStorageProvider`,
  `pszKeyName`, `pcbResult`) and the constants keep the Windows spelling in SCREAMING_SNAKE_CASE
  (`NCRYPT_PAD_PKCS1_FLAG`). Do not rename them to C# conventions, they are meant to be greppable
  against the Windows headers. Only `SECURITY_STATUS` and those constants may look like that.
- `src/.editorconfig` also enforces braces everywhere, no multiple blank lines, four spaces, CRLF,
  UTF-8, file scoped namespaces, `System` usings sorted first and `IDE0005` as warning. Analyzer
  warnings are fixed, not silenced.
- The XML doc comments use two different indentations (`/// <summary>` with and without a leading
  space before the text). Both exist side by side in `WinHelloProvider.cs`, leave the existing ones
  alone.

## Known quirks

Do not silently "clean up" these, they are existing behaviour:

- **The tests need a real Windows Hello and a human.** `WinHelloProvider.CreateInstance` throws
  `AuthProviderIsUnavailableException` on a machine without Hello enrolled, and `PromptToDecrypt`
  opens the Hello dialog and waits for a gesture. `dotnet test` is therefore interactive and cannot
  run on a build server. On top of that the tests create real persistent keys in the current user's
  key storage provider (`<SID>//WindowsHello//` plus `WindowsHello` or `Test`) with
  `overwriteExisting: true` and never delete them. Never claim a test run happened without running
  it, and expect it to hang if nobody answers the prompt.
- **Almost all state is static.** `instance`, `uiContext`, `currentKeyName` and `persistentKeyName`
  are static fields of `WinHelloProvider`, guarded by the static `Mutex`. Two calls to
  `CreateInstance` with different messages therefore share one state: the second call overwrites
  `uiContext` and `currentKeyName` while `instance ??=` returns the object from the first call.
  Since all state is static, both objects behave identically, so this is a trap rather than a bug,
  but it does mean the library supports exactly one key at a time per process.
- **`Encrypt` is silent, `PromptToDecrypt` is not.** `Encrypt` opens the key with
  `CngKeyOpenOptions.Silent` and never shows UI. `PromptToDecrypt` opens it with
  `CngKeyOpenOptions.None`, sets `NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY` and therefore
  forces a fresh gesture on every single call, even when Windows would still have a cached PIN.
- **RSA 2048 with PKCS#1 padding, so 245 bytes maximum.** `CreatePersistentKey` hardcodes
  `NCRYPT_LENGTH_PROPERTY` to 2048 and both directions pass `NCRYPT_PAD_PKCS1_FLAG`. Longer input
  fails inside `NCryptEncrypt` and surfaces as `AuthProviderSystemErrorException`. The library is
  meant for a key or a secret, not for a file. `PromptToDecrypt` sizes its output buffer as
  `data.Length * 2` and resizes it afterwards, the `// TODO: secure resize` comment above that line
  is the original author's.
- **`NCRYPT_NGC_CACHE_TYPE_PROPERTY` has two spellings.** `CreatePersistentKey` and
  `VerifyPersistentKeyIntegrity` both try `"NgcCacheType"` first and fall back to the deprecated
  `"NgcCacheTypeProperty"` inside a `catch`. Older Windows builds only know the second one. Both
  paths are needed, and the empty `catch` is deliberate.
- **The integrity check is the security fix from 1.0.4.0.**
  `VerifyPersistentKeyIntegrity` rejects a key that carries `NCRYPT_ALLOW_KEY_IMPORT_FLAG` or whose
  cache type is not `AUTH_MANDATORY`, and the constructor deletes such a key and throws
  `AuthProviderInvalidKeyException`. That is what stops an attacker from swapping in an imported
  key. Do not weaken or skip it.
- **`IsAvailable` judges by an empty string.** `NgcGetDefaultDecryptionKeyName` from
  `cryptngc.dll` is undocumented, its status code is deliberately not passed through `CheckStatus`,
  and availability is decided by whether the returned key name is empty. The result is cached in a
  `Lazy<string>` for the lifetime of the process, so enrolling Hello while the process runs is not
  noticed.
- **`SubDomain` is an empty constant.** The key name is built as
  `<SID>//WindowsHello/<SubDomain>/<name>`, and with `SubDomain = ""` that leaves a double slash in
  the middle. Changing the constant or the format string invalidates every existing key, because the
  name is how the key is found.
- **`SetPersistentKeyName` switches the key only since 1.1.5.0.** Up to 1.1.4.0 the setter stored
  the new name in `persistentKeyName` and stopped there, while `Encrypt` and `PromptToDecrypt` read
  `currentKeyName`, which the constructor had set to the default name. The name passed in was
  therefore ignored. Since 1.1.5.0 the setter also creates the key when it does not exist and moves
  `currentKeyName` over, so the first call for an unknown name shows the Hello dialog. Anything an
  application encrypted with 1.1.4.0 or older after calling the setter sits under the **default**
  key, not under the named one.
- **`SetPersistentKeyName` sanitizes with two `Replace` calls.**
  `Replace("/", string.Empty).Replace("//", string.Empty)` is redundant, after the first call no
  slash is left. It is harmless and stays.
- **WinForms for one interface.** `UseWindowsForms` is only there so that
  `AuthProviderUiContext` can implement `IWin32Window`. Nothing draws a window, and the property is
  never read by the library itself, only `ParentWindowHandle` is.
- **`[Serializable]` without serialization support.** All seven exceptions carry the attribute but
  none implements the `(SerializationInfo, StreamingContext)` constructor, so binary serialization
  would not round trip. The attribute is part of the published API surface since 1.0, it stays.
  `AuthProviderInvalidKeyException` is the odd one out with a `protected` parameterless
  constructor while its siblings have public ones.
- **`Windows.ico` exists three times.** `src/Windows.ico`, `src/WindowsHello/Windows.ico` and
  `src/WindowsHello.Tests/Windows.ico` are all tracked, all 165 KB. Only the test project
  references its copy, through `ApplicationIcon` on a project whose `OutputType` is `Library`,
  where an application icon has no effect. The other two are unreferenced. Leave them, removing
  them is churn without a benefit.
- **`GeneratePackageOnBuild` leaves old packages in `bin/Release`.** After a few builds the folder
  holds several `.nupkg` and `.snupkg` files, including prerelease ones such as `1.1.5-3`.
  `BuildAndPushPackage.bat` pushes `*.nupkg` with a wildcard, which is only safe because the script
  deletes every `bin` and `obj` first. Never push from a folder you did not clean.
- **`BuildAndPushPackage.bat` needs two environment variables** (`NUGET_API_KEY`, `GITHUB_API_KEY`)
  and two configured sources named `nuget.org` and `github`. It ends with `PAUSE`, so it is meant
  to be double clicked, and `cd .\src` at the top makes it relative to the repository root. Every
  push line starts with `@` and the script never turns echo on: with echo on, cmd writes the
  command line to the console **after** expanding the variables, which puts both API keys on
  screen and into every captured log. Do not remove those `@` characters.
- **AppVeyor badge without CI in the repository.** `README.md` links an AppVeyor build that is
  configured outside of this repository. There is no pipeline file here.
- **`src/WindowsHello.sln.DotSettings`** is tracked and holds nothing but a ReSharper user
  dictionary (`BCRYPT`, `cryptngc`, `Haemmer`, `H_00E4mmer`, `KEYSET`, `NCRYPT`, `PKCS`, `ppsz`).
  Leave it alone. The `.user` file next to it is ignored by `.gitignore`.
- **`.gitattributes` sets `* text=auto`** and every rule of the Visual Studio template below it is
  commented out. There is no binary file in the repository that needs a rule, `Icon.png` and the
  three `.ico` files are handled by git's own heuristic.

## Releasing

**Every new version is released completely.** Changelog, README, nuget.org, GitHub Packages and a
GitHub release belong to every version, none of these steps is optional and none of them waits for
a separate request.

1. Make the change.
2. Add an entry at the top of `Changelog.md` in the existing format:
   `* **Version 1.1.5.0 (2026-08-19)** : Short description.`
3. Update `PackageReleaseNotes` in `src/WindowsHello/WindowsHello.csproj` to the same text, in the
   format `Version 1.1.5.0 (2026-08-19): Short description.` This is the one place where a version
   number is written by hand, GitVersion does not fill it.
4. Update `README.md` for every version. The `## Available for` list has to match the target
   frameworks, the usage sample has to compile against the current API, and nothing there may
   describe a state the package has left behind.
5. Commit that.
6. Tag the commit with the plain version number, no `v` prefix (`1.1.5`, `1.1.4`, ...). The existing
   tags are lightweight tags, create new ones the same way.
7. Push the commits and the tag.
8. Only then build the package, and build it while the tag is the newest commit. GitVersion takes
   the version from the tag plus the distance to it, so a build before the tag or after another
   commit produces a prerelease version like `1.1.6-3+Branch.master.Sha...`, and that version would
   end up on nuget.org. `git describe --tags` has to answer with the plain tag.
9. Publish to nuget.org with `BuildAndPushPackage.bat`, started from the repository root, its first
   line is `cd .\src`. It deletes every `bin` and `obj` below `src`, builds `-c Release` and pushes
   the `.nupkg` and the `.snupkg` to nuget.org with `%NUGET_API_KEY%` and to the NuGet source named
   `github` with `%GITHUB_API_KEY%`. It ends with `PAUSE`, so it wants a console. Call it with its
   full path: the Claude Code shell sets `NoDefaultCurrentDirectoryInExePath=1`, so cmd does not
   find a bare `BuildAndPushPackage.bat` in the current directory. Because it always rebuilds, it
   is only correct as long as no commit sits on top of the tag. If one does, push the package that
   was built from the tagged state instead, by its file name and not with the wildcard, because
   `GeneratePackageOnBuild` leaves a `.nupkg` of every intermediate build in `bin`:
   `dotnet nuget push HaemmerElectronics.SeppPenner.WindowsHello.1.1.5.nupkg -s "nuget.org" --skip-duplicate -k %NUGET_API_KEY%`
   in `src/WindowsHello/bin/Release`. That command takes the matching `.snupkg` with it. A push to
   nuget.org cannot be taken back, the version is burned even after unlisting. nuget.org needs a
   few minutes to validate a new version before it is listed.
10. Publish the same `.nupkg` to GitHub Packages,
    `https://nuget.pkg.github.com/SeppPenner/index.json`. The script only reaches it if a NuGet
    source named `github` is registered on the machine, `dotnet nuget list source` shows that. On
    2026-11-24 only nuget.org was registered here, so the two `github` lines of the script fail and
    the push has to be done by hand in `src/WindowsHello/bin/Release`:
    `dotnet nuget push HaemmerElectronics.SeppPenner.WindowsHello.1.1.5.nupkg -s https://nuget.pkg.github.com/SeppPenner/index.json --skip-duplicate --api-key <token>`.
    The API key is a GitHub token with the scope `write:packages`, for example from
    `gh auth token`. If `gh auth status` lists no `write:packages`, the user has to run
    `gh auth refresh -h github.com -s write:packages,read:packages`, it needs a browser login.
    GitHub Packages takes no symbol packages, push the `.nupkg` only.
11. Create the GitHub release:
    `gh release create 1.1.5 -R SeppPenner/WindowsHello --verify-tag --latest --title "Version 1.1.5.0 (2026-08-19)" --notes-file <file>`.
    The notes are the changelog sentence plus the line
    `NuGet: https://www.nuget.org/packages/HaemmerElectronics.SeppPenner.WindowsHello/1.1.5`. Write
    credits as `` `@name` `` in backticks, a bare `@name` notifies that person again.

The version in the `Changelog.md` has four parts (`1.1.5.0`), the tag has three (`1.1.5`).
GitVersion turns the tag into the assembly version.

nuget.org holds 1.0.0, 1.0.0.1, 1.0.2 to 1.0.8 and 1.0.10 to 1.1.5. The tags start with 1.0.3, and
the tag 1.0.9 was never published on nuget.org. On 2026-11-24 no tag had a GitHub release yet, and
GitHub Packages held 1.0.7, 1.0.8, 1.0.10 to 1.0.12 and 1.1.2 to 1.1.5, the older history there is
incomplete.

## Git

- **Never amend a commit.** No `git commit --amend`, not for a typo in the message, not to add a
  forgotten file, not even when the commit is still local. Write a follow-up commit instead. The
  release versions come from tags on exact commits, an amended commit leaves its tag pointing at a
  commit that no longer exists in the branch.

## Writing style

- Commit messages are written **in English only**: short, precise subject line, explanatory body
  when needed.
- Code comments and comments in project files such as `.csproj` are **always English**, regardless
  of the language used in the conversation.
- **No em dashes or en dashes** (`—`, `–`), neither in prose, commit messages, code comments nor
  documentation. Use a regular hyphen, comma, colon, parentheses or a separate sentence.
- German texts (documentation, chat replies) always use real umlauts and ß, never ASCII
  transliterations such as `ae`, `oe`, `ue` or `ss`. Identifiers, file names and configuration keys
  stay unchanged where umlauts are technically undesirable.
