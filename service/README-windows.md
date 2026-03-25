# Windows Service Setup

## Task Scheduler (recommended)

Run in an elevated PowerShell:

```powershell
schtasks /create /tn "SystemMonitor" /tr "C:\path\to\system-monitor.exe daemon" /sc onlogon /rl limited
```

Replace `C:\path\to\system-monitor.exe` with the actual path to the binary.

## Manual start

```powershell
system-monitor.exe daemon
```

## Remove the scheduled task

```powershell
schtasks /delete /tn "SystemMonitor" /f
```
