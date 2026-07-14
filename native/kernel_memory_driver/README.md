# Signed lab kernel-memory driver

This directory contains the minimal driver-side contract consumed by
`KernelDriverMemoryProvider`. It is a legacy WDM laboratory driver, not a
general process-memory interface.

## Contract boundaries

The device is fixed at `\\.\ReverseAnalyzerKernelMemory` and its ACL grants
access only to `SYSTEM` and Administrators. The only accepted IOCTLs are:

- protocol version query;
- identity query for one configured PID and creation time;
- a read of at most 64 KiB inside one configured user-address interval;
- compare-before-write of at most 4 KiB inside that same interval.

Every process operation verifies both the configured PID and
`PsGetProcessCreateTimeQuadPart`. Reads and writes reject kernel addresses,
integer wraparound, short buffers, unknown protocol versions, unexpected
payload fields, zero request correlation identifiers, and requests outside the
configured interval. Writes are off
by default and never change page protection. The driver does not implement
allocation, injection, hooks, hidden objects, handle bypasses, arbitrary
process selection, or arbitrary IOCTL forwarding.

## Build dependencies

- Visual Studio 2022 with Desktop C++ tools;
- Windows 11 SDK and a matching Windows Driver Kit;
- an x64 `Windows Kernel Mode Driver, Empty (WDM)` project targeting Windows
  10 version 2004 or newer (`ExAllocatePool2` is used);
- `Wdmsec.lib` in Linker > Input > Additional Dependencies.

Add `driver.c` and `protocol.h` to the empty project, set the target name to
`ReverseAnalyzerKernelMemory`, and build an x64 Release configuration. Copy
the resulting `.sys` beside `ReverseAnalyzerKernelMemory.inf`, then create a
catalog with `Inf2Cat` for the lab OS versions.

Example Developer PowerShell commands after the WDK build:

```powershell
Inf2Cat.exe /driver:. /os:10_X64,Server10_X64
New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=Reverse Analyzer Kernel Lab" -CertStoreLocation Cert:\LocalMachine\My
signtool.exe sign /v /fd SHA256 /s My /n "Reverse Analyzer Kernel Lab" ReverseAnalyzerKernelMemory.cat
signtool.exe sign /v /fd SHA256 /s My /n "Reverse Analyzer Kernel Lab" ReverseAnalyzerKernelMemory.sys
```

The certificate must be trusted by the isolated lab host. Test-signing mode
and its required reboot are host configuration, not actions performed by this
repository.

## Install and configure

Install the primitive driver package or copy the signed `.sys` to a stable lab
path and create a demand-start kernel service:

```powershell
sc.exe create ReverseAnalyzerKernelMemory type= kernel start= demand binPath= "C:\Lab\ReverseAnalyzerKernelMemory.sys"
$parameters = "HKLM:\SYSTEM\CurrentControlSet\Services\ReverseAnalyzerKernelMemory\Parameters"
New-Item -Path $parameters -Force
New-ItemProperty -Path $parameters -Name AllowedPid -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path $parameters -Name AllowedCreationTime -PropertyType QWord -Value 0 -Force
New-ItemProperty -Path $parameters -Name AllowedBaseAddress -PropertyType QWord -Value 0 -Force
New-ItemProperty -Path $parameters -Name AllowedRegionSize -PropertyType QWord -Value 0 -Force
New-ItemProperty -Path $parameters -Name AllowWrite -PropertyType DWord -Value 0 -Force
```

All zero values intentionally leave process operations disabled. Before
starting the service, set exactly one target identity and one bounded address
interval. `AllowedCreationTime` is the target process creation `FILETIME`,
which can be obtained in PowerShell with:

```powershell
$process = Get-Process -Id <pid>
$creationTime = [UInt64]$process.StartTime.ToUniversalTime().ToFileTimeUtc()
```

Set `AllowWrite=1` only for an explicit repair session. Configuration is read
once at driver load, so stop the service before changing it and start it after
all values are committed.

## Optional real smoke

The Python test remains skipped unless the signed driver is installed and
the gate is explicit:

```powershell
$env:RUN_KERNEL_MEMORY_SMOKE = "1"
python -m unittest -v tests.test_kernel_memory_provider.KernelMemoryDriverSmokeTests
```

The version probe runs first. An allowlisted read additionally requires
`KERNEL_MEMORY_SMOKE_PID`, `KERNEL_MEMORY_SMOKE_CREATION_TIME`,
`KERNEL_MEMORY_SMOKE_ADDRESS`, and `KERNEL_MEMORY_SMOKE_SIZE`.
