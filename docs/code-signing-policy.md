# Code signing policy

Free code signing provided by [SignPath.io](https://signpath.io), certificate by
[SignPath Foundation](https://signpath.org).

This document describes how the Windows binaries of WinCleaner are built and
signed. It is referenced from the project home page (the README of this
repository) and from every release on the
[Releases page](https://github.com/nicomil/wincleaner/releases).

## What is signed

| Artifact | Signed | Notes |
|---|---|---|
| `WinCleaner-Setup-<version>-<arch>.exe` | yes | Inno Setup installer, the only download offered to users |
| `WinCleaner.exe`, `wchelper.exe` | yes | inside the installer |
| `WinCleaner.Core.dll`, `WinCleaner.Modules.dll` | yes | inside the installer |
| `WinCleaner.dll` | no | its SHA-256 is compiled into `wchelper.exe` before signing (see below) |
| .NET runtime and Windows App SDK files | not by us | they keep Microsoft's own signatures |
| `unins000.exe` (the uninstaller) | no | created by Inno Setup at build time |

`wchelper.exe` is the only part of WinCleaner that runs as administrator. It
only serves a `WinCleaner.exe` that sits in its own folder, carries an intact
signature from the expected certificate, and ships with the `WinCleaner.dll`
whose SHA-256 was compiled into the helper. That hash is taken before signing,
so `WinCleaner.dll` itself stays unsigned; its integrity is guaranteed by the
hash and by the signed `wchelper.exe` that checks it.

## How releases are built

- The official repository is https://github.com/nicomil/wincleaner. Only code
  from this repository is signed.
- Every release is built by the GitHub Actions workflow
  [`release.yml`](../.github/workflows/release.yml) on GitHub-hosted runners,
  from a tag `v<version>` that matches the version in `Directory.Build.props`.
  Builds made on a developer's machine are never submitted for signing.
- The workflow uploads the unsigned binaries as a GitHub Actions artifact and
  submits them to SignPath with the
  [`signpath/github-action-submit-signing-request`](https://github.com/signpath/github-action-submit-signing-request)
  action. SignPath verifies that the artifact was produced by that workflow run.
- Two signing requests are made per release: one for the executables and
  libraries, one for the installer built from the signed files. Each request
  waits for manual approval by an approver (below) before the certificate is
  used.
- NuGet packages are restored in locked mode (`packages.lock.json`) and the
  build fails on any package with a known vulnerability.

## Team and roles

| Role | Member | Responsibility |
|---|---|---|
| Author | Nicola Milella ([@nicomil](https://github.com/nicomil)) | commits to the repository |
| Reviewer | Nicola Milella | reviews every change from non-committers (pull requests) before it is merged; build scripts and workflow files get particular attention |
| Approver | Nicola Milella | approves each signing request in SignPath after checking that it comes from a release tag of this repository |

All team members use multi-factor authentication on GitHub and on SignPath.

## Privacy policy

WinCleaner does not collect or send any data about you or your PC. It has no
telemetry, no account, no crash reporting and no update check of its own.

Some functions start tools that ship with Windows, which may contact Microsoft
on their own terms: the *Updates* page runs the Windows Package Manager
(`winget`), the *Protection* page queries Microsoft Defender through WMI and
can run `MpCmdRun.exe`. Nothing is sent by WinCleaner itself. Everything the
app does is written to a local log in `%LOCALAPPDATA%\WinCleaner\Logs`
(operations made as administrator in `C:\ProgramData\WinCleaner\Helper\Logs`).

## System changes and uninstallation

WinCleaner is a cleaning and maintenance tool, so it changes the system on
purpose: it removes files, registry entries, startup entries and programs,
always after an explicit request and a confirmation that lists what will be
done. Files go to the Recycle Bin by default, registry keys are exported to a
`.reg` backup before removal, and operations that need administrator rights go
through `wchelper.exe` after a UAC prompt. The *Dry run* mode changes nothing.

Uninstall from *Settings → Apps → WinCleaner → Uninstall* (or run
`unins000.exe` in the installation folder). The uninstaller removes the
program, its Start menu entry, the scheduled analysis and the start-with-
Windows entry; the data in `%LOCALAPPDATA%\WinCleaner` is kept and can be
deleted by hand.

## Verifying a download

Right-click the installer → *Properties* → *Digital Signatures*: the signer
must be **SignPath Foundation**. Each release also lists the SHA-256 of its
files; on Windows, `Get-FileHash <file>` in PowerShell prints it.
