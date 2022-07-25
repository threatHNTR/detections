# Reboot to Windows Safe Mode to Bypass AV Tools via BCDEdit

## Description

Windows Safe Mode is a special startup mode that allows users to run administrative and diagnostic tasks on the operating system. This mode only loads the bare minimum of software and drivers required for the operating system to work. Furthermore, any programs installed in Windows that are configured to start automatically will not start in Safe Mode unless their autorun is configured a certain way. Ransomware operators has added a new ability to encrypt files in Windows Safe Mode, likely to evade detection by security software and for greater success when encrypting files.

## Detection

```
(process_name:bcedit.exe AND (process_cmdline:\/set AND process_cmdline:safeboot AND (process_cmdline:minimal OR process_cmdline:network)))
```

## References
 - https://www.bleepingcomputer.com/news/security/revil-ransomware-has-a-new-windows-safe-mode-encryption-mode/
 - https://www.bleepingcomputer.com/news/security/snatch-ransomware-reboots-to-windows-safe-mode-to-bypass-av-tools/
 - https://posts.specterops.io/capability-abstraction-case-study-detecting-malicious-boot-configuration-modifications-1852e2098a65
 - https://twitter.com/rfackroyd/status/1547233931015213056
