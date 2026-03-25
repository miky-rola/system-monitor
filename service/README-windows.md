# Windows Service Setup

## Task Scheduler (recommended)

Run in an elevated PowerShell. This auto-detects the binary location:

```powershell
schtasks /create /tn "SystemMonitor" /tr "\"$(where.exe system-monitor)\" daemon" /sc onlogon /rl limited
```

If `system-monitor` is not on your PATH, specify the full path manually:

```powershell
schtasks /create /tn "SystemMonitor" /tr "C:\Users\YourName\Downloads\system-monitor.exe daemon" /sc onlogon /rl limited
```

## Manual start

```powershell
system-monitor daemon
```

## Remove the scheduled task

```powershell
schtasks /delete /tn "SystemMonitor" /f
```
