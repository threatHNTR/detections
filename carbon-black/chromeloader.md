# ChromeLoader Malware

## Description

ChromeLoader is a pervasive and persistent browser hijacker that modifies its victims' browser settings and redirects user traffic to advertisement websites. This malware is introduced via an ISO file that baits users into executing it by posing as a cracked video game or pirated movie or TV show. It eventually manifests as a browser extension. 

## Response

This alert is designed to detect instances of the Chrome browser executable spawning from PowerShell with a corresponding command line that includes appdata\local as a parameter. ChromeLoader loads its extension into Chrome by using PowerShell to spawn Chrome with the --load-extension flag and references the file path of the downloaded extension. Analyze the extension loaded into Chrome. Look for the initial access point, normally an ISO file that has been downloaded. Looks for suspicious executables dropped in the AppData\Roaming folder. Check for instances of scheduled tasks and registry run keys for persistence. Look for possible data exfiltration.

## Detection

```
((parent_name:powershell.exe OR parent_name:pwsh.exe) AND process_name:chrome.exe AND process_cmdline:\-\-load\-extension\=* AND process_cmdline:\\AppData\\Local\\)
```

## References
- https://blogs.vmware.com/security/2022/09/the-evolution-of-the-chromeloader-malware.html
- https://unit42.paloaltonetworks.com/chromeloader-malware/
- https://redcanary.com/blog/chromeloader/
