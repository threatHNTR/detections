# MSDT DogWalk

## Description

DogWalk takes advantage of the Microsoft Troubleshoot component baked into modern versions of Windows except this time the exploit lies in .diagcab files which can be used by a threat actor to download files to the victim’s computer. In short, these files contain diagnostic information and resources that can be modified by an attacker to download a .exe file into an unsuspecting user’s startup folder, for example.

![Doglwalk](https://www.securonix.com/wp-content/uploads/2022/06/Picture1.gif)

## Detection

```
(process_name:msdt.exe AND process_cmdline:\/cab AND process_cmdline:\\*.diagcab)
```

## References
- https://irsl.medium.com/the-trouble-with-microsofts-troubleshooters-6e32fc80b8bd/
- https://thehackernews.com/2022/06/researchers-warn-of-unpatched-dogwalk.html
- https://www.securonix.com/blog/detecting-microsoft-msdt-dogwalk/
