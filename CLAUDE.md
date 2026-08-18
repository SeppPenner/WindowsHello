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

- `src/WindowsHello/WindowsHello.csproj`, the library. Multi-targets `net8.0-windows` and
  `net9.0-windows`, `UseWindowsForms` enabled.
- `src/WindowsHello.Tests/WindowsHello.Tests.csproj`, MSTest, `net9.0-windows`, `IsPackable`
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
contributors table), `Changelog.md`, `Updating.md` (the five release steps), `License.txt` (MIT),
`Icon.png` (the package icon), `BuildAndPushPackage.bat`, `Delete-BIN-OBJ-Folders.bat`,
`.all-contributorsrc`, `.gitattributes` and `.gitignore`. There is no `.github` folder, no
`HowToUse.md` and no screenshots.

## Build

```powershell
dotnet build src/WindowsHello.sln -c Release
```

```powershell
dotnet test src/WindowsHello.sln
```

- The library multi-targets `net8.0-windows` and `net9.0-windows`, the test project builds for
  `net9.0-windows` only. `RuntimeIdentifiers` is `win-x64`.
- All build properties live directly in the two `.csproj` files. `src/Directory.Build.props` exists
  but sets nothing except `GenerateDocumentationFile`, which is why every type and member needs an
  XML doc comment.
- `TreatWarningsAsErrors` is enabled in both projects, so every warning breaks the build, NuGet
  warnings (`NU****`) from restore included. A clean build reports zero warnings, keep it that way.
- `NU1803` (HTTP source usage during restore) is the one warning suppressed via `NoWarn`. Fix
  warnings instead of extending that list. `NuGetAudit` is not configured, so restore only reports
  a vulnerable package when the default audit level does.
- Versions come from GitVersion.MsBuild out of the git tags, for example `1.1.5-3` for the third
  commit after tag `1.1.4`. Never edit an assembly version by hand. The one version string that
  **is** maintained by hand is `PackageReleaseNotes` in `WindowsHello.csproj`, see "Releasing".
- Restore needs nuget.org. If a private feed is configured globally on the machine and answers 404
  for public packages, restore fails with `NU1301`. Then build with an explicit source:
  `dotnet build src/WindowsHello.sln --source https://api.nuget.org/v3/index.json`.
- Building for `net8.0-windows` works without a .NET 8 SDK on the machine, the reference packs come
  from NuGet. A newer SDK is enough for the whole solution.
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
  to be double clicked, and `cd .\src` at the top makes it relative to the repository root.
- **AppVeyor badge without CI in the repository.** `README.md` links an AppVeyor build that is
  configured outside of this repository. There is no pipeline file here.
- **`src/WindowsHello.sln.DotSettings`** is tracked and holds nothing but a ReSharper user
  dictionary (`BCRYPT`, `cryptngc`, `Haemmer`, `H_00E4mmer`, `KEYSET`, `NCRYPT`, `PKCS`, `ppsz`).
  Leave it alone. The `.user` file next to it is ignored by `.gitignore`.
- **`.gitattributes` sets `* text=auto`** and every rule of the Visual Studio template below it is
  commented out. There is no binary file in the repository that needs a rule, `Icon.png` and the
  three `.ico` files are handled by git's own heuristic.

## Releasing

1. Make the change.
2. Add an entry at the top of `Changelog.md` in the existing format:
   `* **Version 1.1.5.0 (2026-08-18)** : Short description.`
3. Update `PackageReleaseNotes` in `src/WindowsHello/WindowsHello.csproj` to the same text. This is
   the one place where a version number is written by hand, GitVersion does not fill it.
4. Commit that.
5. Tag the commit with the plain version number, no `v` prefix (`1.1.5`, `1.1.4`, ...). The existing
   tags are lightweight tags, create new ones the same way.
6. Only now build the package, because GitVersion reads the tag. Without the tag the package gets a
   prerelease version such as `1.1.5-3` and is unusable as a release.
7. `BuildAndPushPackage.bat` builds and pushes to nuget.org and to the GitHub package feed.
8. Push the commits and the tag.

The version in the `Changelog.md` has four parts (`1.1.5.0`), the tag has three (`1.1.5`).
GitVersion turns the tag into the assembly version. A published NuGet version can never be
replaced, so the tag has to be right before the push, not after.

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
