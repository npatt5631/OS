```
https://os.cybbh.io/public
```
```
https://cctc.cybbh.io/students
```
______________________________________________________________________________________________________________________________________________________________________________________
```
http://10.50.22.129:8000/
```
## MARO-M-007

## M24007 password

## Stack 1: student@10.50.25.34 password
______________________________________________________________________________________________________________________________________________________________________________________
# |
# |
# |
# |
# |
# 01_windows_powershell
______________________________________________________________________________________________________________________________________________________________________________________
### 1: Which program starts with every CMD and PowerShell instance in Windows 7 and later? - ``` ConHost.exe ```
______________________________________________________________________________________________________________________________________________________________________________________
### 2: What Windows 10 feature supports installing Linux subsystem? - ``` WSL ```
______________________________________________________________________________________________________________________________________________________________________________________
### 3: Which Windows feature can be used to interact with any CLI on the Windows system concurrently using multiple tabs? - ``` Windows Terminal ```
______________________________________________________________________________________________________________________________________________________________________________________
### 4: What was the default shell (command line) of Windows versions Windows 2000 through Windows 8.1? - ``` CMD ```
______________________________________________________________________________________________________________________________________________________________________________________
### 5: What data type do all cmd.exe commands return? - ``` String ```
______________________________________________________________________________________________________________________________________________________________________________________
### 6: What framework is PowerShell built on? - ``` .net ```
______________________________________________________________________________________________________________________________________________________________________________________
### 7: "What will all of the below give you? - ``` powershell version ```
#### (get-host).version

#### $host.version

#### $psversiontable.psversion"
______________________________________________________________________________________________________________________________________________________________________________________
### 8: After PowerShell Core is installed what CLI command launches it? - ``` pwsh.exe ```
______________________________________________________________________________________________________________________________________________________________________________________
### 9: "After PowerShell Core is installed you can still run the built in version of PowerShell side-by-side. What CLI command will launch the built in version?" - ``` PowerShell.exe ```
______________________________________________________________________________________________________________________________________________________________________________________
### 10: What syntax do PowerShell cmdlets follow? - ``` Verb-Noun ```
______________________________________________________________________________________________________________________________________________________________________________________
### 11: What PS command will list all PowerShell cmdlets? - ``` Get-Command ```
______________________________________________________________________________________________________________________________________________________________________________________
### 12: What PowerShell command will list all verbs? - ``` Get-Verb ```
______________________________________________________________________________________________________________________________________________________________________________________
### 13: BASH commands output strings. PowerShell commands output what data type? - ``` Objects ```
______________________________________________________________________________________________________________________________________________________________________________________
### 14: All PowerShell objects are comprised of what two things? - ``` properties, methods ```
______________________________________________________________________________________________________________________________________________________________________________________
### 15: What command will list all things that make up a PowerShell object? - ``` Get-Member ```
______________________________________________________________________________________________________________________________________________________________________________________
### 16: What PowerShell command will list PowerShell aliases? - ``` Get-Alias ```
______________________________________________________________________________________________________________________________________________________________________________________
### 17: What PowerShell command lists all of the contents of a directory? - ``` Get-Childitem ```
______________________________________________________________________________________________________________________________________________________________________________________
### 18: What is the basic cmdlet that displays help about Windows Powershell cmdlets and concepts? - ``` Get-Help ```
______________________________________________________________________________________________________________________________________________________________________________________
### 19: PowerShell "help files" don't show the entire help file with a basic command. What switch option shows the entire help file? - ``` -Full ```
______________________________________________________________________________________________________________________________________________________________________________________
### 20: What PowerShell command will update the PowerShell "help files" to the latest version? - ``` Update-Help ```
______________________________________________________________________________________________________________________________________________________________________________________
### 21: What help switch will show you the "help files" on Microsoft's website, in your default browser? - ``` -Online ```
______________________________________________________________________________________________________________________________________________________________________________________
### 22: What command will start the Chrome browser on your machine? - ``` Start-Process "Chrome.exe" ```
______________________________________________________________________________________________________________________________________________________________________________________
### 23: What command using a PS Method will stop chrome? - ``` (Get-Process chrome*).kill() ```
______________________________________________________________________________________________________________________________________________________________________________________
### 24: What PowerShell command (without using a method) will stop the Chrome process? - ``` Stop-Process -Name "chrome" ```
______________________________________________________________________________________________________________________________________________________________________________________
### 25: PowerShell doesn't have a native cmdlet that will give you processor information (such as get-processor or get-cpu). Knowing this information might be necessary. What command would give you information about the system's processor? - ``` Get-CimInstance -ClassName Win32_Processor ```
______________________________________________________________________________________________________________________________________________________________________________________
### 26: What PowerShell command will read a text file? - ``` Get-Content ```
______________________________________________________________________________________________________________________________________________________________________________________
### 27: What PowerShell command will allow for counting lines in a file, averaging numbers, and summing numbers? - ``` Measure-Object ```
______________________________________________________________________________________________________________________________________________________________________________________
### 28: What PowerShell command searches for text patterns in a string? - ``` Select-String ```
______________________________________________________________________________________________________________________________________________________________________________________
### 29: Users' files are stored in their corresponding home directory. What is the literal path to all home directories on a Windows 10 system? - ``` C:\Users ```
______________________________________________________________________________________________________________________________________________________________________________________
### 30: How many properties are available for the get-process cmdlet? - ``` 52 ```
______________________________________________________________________________________________________________________________________________________________________________________
### 31: How many aliases does PowerShell have for listing the contents of a directory? - ``` 3 ```
______________________________________________________________________________________________________________________________________________________________________________________
### 32: When requesting the help file for the get-process cmdlet, what full command is the 9th example given? - ``` Get-Process Powershell ```
______________________________________________________________________________________________________________________________________________________________________________________
### 33: To complete this challenge, find the description of the Lego Land service. - ``` i_love_legos ```

        Get-WMIObject WIN32_service | ?{$_.Name -like "legoland"} | select Description
______________________________________________________________________________________________________________________________________________________________________________________
### 34: In the CTF folder on the CTF User's Desktop, count the number of words in words2.txt. - ``` 5254 ```

        Get-Content words2.txt | Measure-Object -Word
______________________________________________________________________________________________________________________________________________________________________________________
### 35: Count the number of files in the Videos folder in the CTF user's home directory. - ``` 925 ```

        (Get-ChildItem | Measure-Object).count
______________________________________________________________________________________________________________________________________________________________________________________
### 36: Find the only line that makes the two files in the CTF user's Downloads folder different. - ``` popeye ```

        Compare-Object -referanceobject (Get-Object old.txt) -differenceobject (get-content new.txt)
______________________________________________________________________________________________________________________________________________________________________________________
### 37: The password is the 21st line from the top, in ASCII alphabetically-sorted, descending order of the words.txt file. - ``` ZzZp ```

        Get-Content words.txt | Sort-Object -descending | Selct-Object -index 21
______________________________________________________________________________________________________________________________________________________________________________________
### 38: Count the number of unique words in words.txt - ``` 456976 ```

        (Get-Content words.txt | Sort-Object | Get-Unique).count
______________________________________________________________________________________________________________________________________________________________________________________
### 39: How many methods are available for the get-process cmdlet? - ``` 19 ```

        (Get-Process | Get-Member -membertype method).count
______________________________________________________________________________________________________________________________________________________________________________________
### 40: Count the number of folders in the Music folder in the CTF user’s profile. - ``` 411 ```

        (Get-ChildItem -recurse | Where-Object {$_.PSIsContainer}).count
______________________________________________________________________________________________________________________________________________________________________________________
### 41: Count the number of times, case-insensitive, gaab is listed in words.txt - ``` 1 ```

        (Get-Content words.txt | select-string -allmatches "gaab").count
______________________________________________________________________________________________________________________________________________________________________________________
### 42: Count the number of words, case-insensitive, with either a or z in a word, in the words.txt file - ``` 160352 ```

        (Get-Content words.txt | Where-Object {$_ -match '(a|z)'}).count
______________________________________________________________________________________________________________________________________________________________________________________
### 43: Count the number of lines, case-insensitive, that az appears in the words.txt file - ``` 2754 ```

        (Get-Content words.txt | Where-Object {$_ -match '(az)'}).count
______________________________________________________________________________________________________________________________________________________________________________________
### 44: Use a PowerShell loop to unzip the Omega file 1,000 times and read what is inside. - ``` kung-fu ```

        mkdir Extracted
        
        $zipPath = 'C:\Users\CTF\Omega1000.zip'; 1000..1 | ForEach-Object { Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, 'C:\Users\CTF\Extracted'); $zipPath = "C:\Users\CTF\Extracted\Omega$($_ - 1).zip" }
        
        cd Extracted
        
        Expand-Archive Omega1.zip
        
        cd Omega1
        
        Expand-Archive Omega1.zip
        
        cd Omega1
        
        type Omega1.txt
______________________________________________________________________________________________________________________________________________________________________________________
### 45: Count the number of words in words.txt that meet the following criteria: - ``` 357 ```

#### a appears at least twice consecutively

#### and is followed immediately by any of the letters a through g

#### Note: File Location - C:\Users\CTF\Desktop\CTF

#### Example: aac...aaa...

        (Get-Content words.txt | Where-Object {$_ -match '((aa)[a-g])'}).count
______________________________________________________________________________________________________________________________________________________________________________________
# |
# |
# |
# |
# |
# 02_windows_powershell_profiles 
______________________________________________________________________________________________________________________________________________________________________________________
### 1: Which PowerShell profile has the lowest precedence? - ``` Current User, Current Host ```
______________________________________________________________________________________________________________________________________________________________________________________
### 2: Which PowerShell profile has the highest precedence? - ``` All Users, All Hosts ```
______________________________________________________________________________________________________________________________________________________________________________________
### 3: Which PowerShell variable stores the current user’s home directory? - ``` $Home ```
______________________________________________________________________________________________________________________________________________________________________________________
### 4: Which PowerShell variable stores the installation directory for PowerShell? - ``` $PsHome ```
______________________________________________________________________________________________________________________________________________________________________________________
### 5: Which PowerShell variable stores the path to the "Current User, Current Host" profile? - ``` $Profile ```
______________________________________________________________________________________________________________________________________________________________________________________
### 6: What command would you run to view the help for PowerShell Profiles? - ``` Get-Help about_profiles ```
______________________________________________________________________________________________________________________________________________________________________________________
### 7: What command would tell you if there was a profile loaded for All Users All Hosts? - ``` Test-Path -Path $PROFILE.AllUsersAllHosts ```
______________________________________________________________________________________________________________________________________________________________________________________
### 8: Malware is running on the primary PowerShell profile on the File-Server. Based on PowerShell profile order of precedence (what is read first), find the correct flag. - ``` I am definitely not the malware ```
______________________________________________________________________________________________________________________________________________________________________________________
# |
# |
# |
# |
# |
# 04_linux_basics2
______________________________________________________________________________________________________________________________________________________________________________________
### 1: This challenge is worth 0 POINTS, and should only be attempted after all other challenges that are open to you, are completed! - ``` ??? ```

File: /home/garviel/NMAP_all_hosts.txt

Format the file into the output displayed below using native Linux binaries like awk

Present the script used to the instructor for credit when complete. Be prepared to explain the code.

HINT: awk is a powerful text manipulation scripting language. It is a bit challenging to learn. Use the tutorials below to get started.

Awk - A Tutorial and Introduction - by Bruce Barnett

The GNU Awk User’s Guide
______________________________________________________________________________________________________________________________________________________________________________________
### 2: What command lists the contents of directories in Linux/Unix systems? - ``` ls ```
______________________________________________________________________________________________________________________________________________________________________________________
### 3: For the ls command, what arguments, or switch options, will allow you to print human-readable file sizes in a long-list format? - ``` ls -hl ```
______________________________________________________________________________________________________________________________________________________________________________________
### 4: What character will pipe the standard output from echo "I’m a plumber" to another command, as standard input? - ``` | ```
______________________________________________________________________________________________________________________________________________________________________________________
### 5: What argument/switch option, when used with man, will search the short descriptions and man-page-names for a keyword that you provide? - ``` man -k ```
______________________________________________________________________________________________________________________________________________________________________________________
### 6: What is the absolute path to the root directory? - ``` / ```
______________________________________________________________________________________________________________________________________________________________________________________
### 7: What is the absolute path to the default location for configuration files? - ``` /etc ```
______________________________________________________________________________________________________________________________________________________________________________________
### 8: What is the directory that contains executable programs (binaries) which are needed in single user mode, to bring the system up or to repair it? - ``` /bin ```
______________________________________________________________________________________________________________________________________________________________________________________
### 9: What is the absolute path to the directory which contains non-essential binaries that are accessible by standard users as well as root? - ``` /usr/bin ```
______________________________________________________________________________________________________________________________________________________________________________________
### 10: An absolute path to a directory which contains binaries only accessible by the root user, or users in the root group. - ``` /sbin ```
______________________________________________________________________________________________________________________________________________________________________________________
### 11: What is the absolute path for the binary cat man-page? - ``` /usr/share/man/man1/cat.1.gz ```

        man --path cat
______________________________________________________________________________________________________________________________________________________________________________________
### 12: Search the man pages for the keyword digest. Then, use one of the binaries listed to hash the string OneWayBestWay using the largest sha hash available. - ``` a81bc463469ee1717fc9e388e3799c653f63a3de5e9496b5707b56488b046cbf75665235d316c5c0053a597dc7d40c917a2d9006fe35e9cb47766c05ac71989b ```

        man -k digest

        echo "OneWayBestWay" | sha512sum
______________________________________________________________________________________________________________________________________________________________________________________
### 13: Use File: /home/garviel/Encrypted this file contains encrypted contents. Identify its file type, then decode its contents. - ``` DeCrypt ```

        $ file Encrypted
        $ unzip Encrypted
        $ file cipher
        $ file symmetric
        $ cat cipher
        $ cat symmetric
            gives you the key & the Hashing Algoritm
        $ openssl AES128 -d -in cipher
            ^use the key that was enumerated from the symmetric file
______________________________________________________________________________________________________________________________________________________________________________________
### 14: Search the user home directories to find the file with the second-most lines in it. The flag is the number of lines in the file. - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 15: Read the file that contains the user database for the machine. Identify a strange comment. - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 16: Identify all members of the lodge group. List their names in alphabetical order with a comma in between each name. - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 17: Find the user with a unique login shell. - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 18: Identify the algorithm, the amount of salted characters added, and the length of the hashed password in the file that stores passwords. - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 19: Find the directory named Bibliotheca. Enter the absolute path to the directory. - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 20: Identify the number of users with valid login shells, who can list the contents of the Bibliotheca directory. - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 21: The permissions that user sejanus has on /media/Bibliotheca, in octal format. - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 22: Locate the file within /media/Bibliotheca that is modifiable by the only user that is part of the chapter group, but not part of the lodge group. - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 23: Identify the file within /media/Bibliotheca where the owning group has more rights than the owning user. - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 24: Execute the file owned by the guardsmen group in /media/Bibliotheca, as the owning user. - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 25: The user tyborc is unable to access the directory: /media/Bibliotheca/Bibliotheca_unus Why? Identify the permission missing in standard verb form. - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 26: Locate the file in /media/Bibliotheca that Quixos has sole modification rights on. - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 27: Read a concealed file within /media/Bibliotheca - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 28: Find the warp and read its secrets for the flag. - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 29: Using the commands ls and grep, identify the number of directories in /etc/ that end in .d - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 30: Use regular expressions to match patterns similar to valid and invalid IP addresses. - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 31: Use regular expressions to match valid IP addresses. The flag is the number of addresses. - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 32: Use regular expressions to match patterns that look similar to a MAC Address. Flag is a count of the number of matches. - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 33: Use awk to print lines: >= 420 AND <=1337 - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 34: Use awk to create a separate CSV (comma separated value) file that contains columns 1-6. - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 35: The garviel user has a minefield map and controls to a Titan War Machine located in their home directory. Interpret the Titan Controls to navigate the minefield and annihilate the target. - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 36: The flag resides in $HOME/paths... you just need to determine which flag it is. The flag sits next to a string matching the name of a $PATH/binary on your system. - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 37: Use regular expressions to find valid Locally Administered or Universally Administered Unicast MAC addresses. Give the count of Locally and Universally Administered MAC addresses as the answer. - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 38: Identify heresy by comparing the Inquisition_Targets file to members of the Guardsmen group. - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
# |
# |
# |
# |
# |
# 05_windows_registry
______________________________________________________________________________________________________________________________________________________________________________________
### 1: What Windows registry path is the Volatile Hive? - ``` HKLM\HARDWARE ```
______________________________________________________________________________________________________________________________________________________________________________________
### 2: What registry key creates the Wow6432Node to represent 32-bit applications that run on a 64-bit version of Windows? - ``` HKEY_LOCAL_MACHINE\SOFTWARE ```
______________________________________________________________________________________________________________________________________________________________________________________
### 3: In what registry path are the BOOT_START drivers located? - ``` HKLM\SYSTEM\CurrentControlSet\Services ```
______________________________________________________________________________________________________________________________________________________________________________________
### 4: What start value do BOOT_START drivers have in the registry? - ``` 0x0 ```
______________________________________________________________________________________________________________________________________________________________________________________
### 5: During kernel initialization, what registry location is read containing all SYSTEM_START drivers? - ``` HKLM\SYSTEM\CurrentControlSet\Services ```
______________________________________________________________________________________________________________________________________________________________________________________
### 6: SERVICE_AUTO_START drivers and services are loaded after kernel initialization. What start value do they have in the registry? - ``` 0x02 ```
______________________________________________________________________________________________________________________________________________________________________________________
### 7: What start value do SERVICE_DEMAND_START drivers and services have in the registry? - ``` 0x3 ```
______________________________________________________________________________________________________________________________________________________________________________________
### 8: When accessing a remote registry which are the only 2 accessible HKEYs? - ``` HKLM, HKU ```
______________________________________________________________________________________________________________________________________________________________________________________
### 9: What PowerShell cmdlet will list currently mapped drives? - ``` Get-PSDrive ```
______________________________________________________________________________________________________________________________________________________________________________________
### 10: What is the native Windows GUI tool for managing the registry? - ``` Registry Editor ```
______________________________________________________________________________________________________________________________________________________________________________________
### 11: What registry hive contains all machine settings? - ``` HKLM ```
______________________________________________________________________________________________________________________________________________________________________________________
### 12: What registry hive contains all user settings? - ``` HKU ```
______________________________________________________________________________________________________________________________________________________________________________________
### 13: What registry hive contains only the currently logged-in user's settings? - ``` HKCU ```
______________________________________________________________________________________________________________________________________________________________________________________
### 14: The HKEY_CURRENT_USER registry hive is a symbolic link to another registry subkey. What is the subkey that it is linked to? - ``` HKU\S-1-5-21-2881336348-3190591231-4063445930-1004 ```
______________________________________________________________________________________________________________________________________________________________________________________
### 15: What PowerShell command will list all the subkeys and contents in the current directory and/or will list all the subkeys and the contents of a directory you specify? - ``` Get-Childitem ```
______________________________________________________________________________________________________________________________________________________________________________________
### 16: What PowerShell command will list only the contents of a registry key or subkey? - ``` Get-Item ```
______________________________________________________________________________________________________________________________________________________________________________________
### 17: What registry subkey runs every time the machine reboots? - ``` HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN ```
______________________________________________________________________________________________________________________________________________________________________________________
### 18: What registry subkey runs every time a user logs on? - ``` HKEY_CURRENT_USER\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN ```
______________________________________________________________________________________________________________________________________________________________________________________
### 19: What registry subkey runs a single time, then deletes its value once the machine reboots? - ``` HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNONCE ```
______________________________________________________________________________________________________________________________________________________________________________________
### 20: What registry subkey runs a single time, then deletes its value when a user logs on? - ``` HKEY_CURRENT_USER\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNONCE ```
______________________________________________________________________________________________________________________________________________________________________________________
### 21: What is the suspicious value inside of the registry subkey from your previous challenge named registry_basics_7?(#17:) - ``` C:\malware.exe ```

        reg query HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN
______________________________________________________________________________________________________________________________________________________________________________________
### 22: What is the suspicious value inside of the registry subkey that loads every time the "Student" user logs on? - ``` C:\botnet.exe ```

        reg query HKEY_CURRENT_USER\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN
______________________________________________________________________________________________________________________________________________________________________________________
### 23: What is the value inside of the registry subkey from registry_basics_9?(#19:) - ``` C:\virus.exe ```

        reg query HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNONCE
______________________________________________________________________________________________________________________________________________________________________________________
### 24: What is the value inside of the registry subkey that loads a single time when the "student" user logs on? - ``` C:\worm.exe ```

        reg query HKEY_CURRENT_USER\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNONCE
______________________________________________________________________________________________________________________________________________________________________________________
### 25: Figure out the manufacturer's name of the only USB drive that was plugged into this machine. - ``` SanDisk9834 ```

        reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR
______________________________________________________________________________________________________________________________________________________________________________________
### 26: What suspicious user profile, found in the registry, has connected to this machine? - ``` Hacker_McHackerson ```

        Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' | Select-Object -Property PSChildName, ProfileImagePath
______________________________________________________________________________________________________________________________________________________________________________________
### 27: What suspicious wireless network, found in the registry, has this system connected to? - ``` Terror_cafe_network ```

        reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\NETWORKLIST\PROFILES\{20A9DB9D-5643-46F7-9FC7-0C382A286301}"
______________________________________________________________________________________________________________________________________________________________________________________
# |
# |
# |
# |
# |
# 06_windows_alternate_data_stream
______________________________________________________________________________________________________________________________________________________________________________________
### 1: The ____ determines how the data is stored on disk. - ``` File System ```
______________________________________________________________________________________________________________________________________________________________________________________
### 2: What are NTFS partition sectors grouped into? - ``` Clusters ```
______________________________________________________________________________________________________________________________________________________________________________________
### 3: What contains the metadata about all of the files and directories on a NTFS partition? - ``` Master File Table ```
______________________________________________________________________________________________________________________________________________________________________________________
### 4: NTFS files are collections of what? - ``` Attributes ```
______________________________________________________________________________________________________________________________________________________________________________________
### 5: Which NTFS attribute would store an alternate data stream? - ``` $DATA ```
______________________________________________________________________________________________________________________________________________________________________________________
### 6: Which NTFS attribute holds information about a file's encrypted attributes? - ``` $LOGGED_UTILITY_STREAM ```
______________________________________________________________________________________________________________________________________________________________________________________
### 7: Which NTFS attribute that is composed of the file security and access control properties? - ``` $SECURITY_DESCRIPTOR ```
______________________________________________________________________________________________________________________________________________________________________________________
### 8: In NTFS, what is the type id, in hex, of the attribute that actually stores a NTFS files contents? - ``` 0x80 ```
______________________________________________________________________________________________________________________________________________________________________________________
### 9: In NTFS what is the maximum number of bytes a MFT entry (containing the entirety of a file) can contain to be considered "Resident Data"? - ``` 1024 ```
______________________________________________________________________________________________________________________________________________________________________________________
### 10: NTFS permissions can be a assigned to a filesystem object in two ways. Which way is intentionally assigned on the file or folder? - ``` Explicit ```
______________________________________________________________________________________________________________________________________________________________________________________
### 11: NTFS permissions can be a assigned to a filesystem object in two ways. Which way is the results of an object being assigned permissions as the result of being the child of another object? - ``` Inherited ```
______________________________________________________________________________________________________________________________________________________________________________________
### 12: Which NTFS file level permission is missing from the following list? Write, Read & Execute, Modify, Full Control - ``` Read ```
______________________________________________________________________________________________________________________________________________________________________________________
### 13: Which NTFS folder level permission is missing from the following list?: Read, Write, Read & Execute, Modify, Full control - ``` List Folder Contents ```
______________________________________________________________________________________________________________________________________________________________________________________
### 14: Which NTFS file level permission permits changing the contents of a file, deleting the file but does not allow the ability to change the permissions on the file? - ``` Modify ```
______________________________________________________________________________________________________________________________________________________________________________________
### 15: Which NTFS folder level permission allows changing permissions? - ``` Full Control ```
______________________________________________________________________________________________________________________________________________________________________________________
### 16: Which NTFS attribute stores the file times of an object? - ``` $STANDARD_INFORMATION ```
______________________________________________________________________________________________________________________________________________________________________________________
### 17: What CLI command will only show the letters of attached drives? - ``` fsutil fsinfo drives ```
______________________________________________________________________________________________________________________________________________________________________________________
### 18: Every file on a Windows system has attributes. What does the d attribute mean? - ``` Directory ```
______________________________________________________________________________________________________________________________________________________________________________________
### 19: Every file on a Windows system has attributes. What does the h attribute mean? - ``` Hidden ```
______________________________________________________________________________________________________________________________________________________________________________________
### 20: What PowerShell command will list all files in the current directory, regardless of their attributes? - ``` Get-Childitem -Force ```
______________________________________________________________________________________________________________________________________________________________________________________
### 21: What PowerShell command will give you the sha512 hash of a file? - ``` Get-FileHash -Algorithm sha512 ```
______________________________________________________________________________________________________________________________________________________________________________________
### 22: What PowerShell command will list permissions of a file? - ``` Get-Acl ```
______________________________________________________________________________________________________________________________________________________________________________________
### 23: What Windows file maps hostnames to IP addresses? - ``` Hosts ```
______________________________________________________________________________________________________________________________________________________________________________________
### 24: Which group has Read and Execute (RX) permissions to the file listed in the previous challenge?(#23) - ``` BUILTIN\Users ```
______________________________________________________________________________________________________________________________________________________________________________________
### 25: Find the last five characters of the MD5 hash of the hosts file. - ``` 7566D ```

        $hostsFilePath = "C:\Windows\System32\drivers\etc\hosts"
        
        $md5Hash = Get-FileHash -Path $hostsFilePath -Algorithm MD5
        
        $lastFiveChars = if ($md5Hash.Hash.Length -ge 5) { $md5Hash.Hash.Substring($md5Hash.Hash.Length - 5) } else { "Hash too short" }
        
        $lastFiveChars
______________________________________________________________________________________________________________________________________________________________________________________
### 26: Examine the readme file somewhere in the CTF user’s home directory. - ``` 123456 ```

        cd c:\Users\CTF
        
        Get-ChildItem -path readme* -Recurse -Force
        
        cd .\Favorites\
        
        Get-Content .\README
______________________________________________________________________________________________________________________________________________________________________________________
### 27: There is a hidden directory in the CTF user's home directory. The directory contains a file. Read the file. - ``` ketchup ```

        Get-ChildItem -path c:\users\ctf -hidden -Recurse -Force -directory

        cd secretsauce

        Get-Content saucey  
______________________________________________________________________________________________________________________________________________________________________________________
### 28: Find a file in a directory on the desktop with spaces in it. FLAG is the contents of the file - ``` 987654321 ```

        Get-ChildItem -Path . -Recurse | Where-Object { $_.Name -like '* *' }
        
        cd C:\Users\CTF\Desktop
        
        cd '.\z                          -                                                                          a\'

        Get-Content .\spaces.txt
______________________________________________________________________________________________________________________________________________________________________________________
### 29: Find the Alternate Data Stream in the CTF user's home, and read it. - ``` P455W0RD ```

        Get-ChildItem -Path "C:\Users\CTF\" -Recurse -File
        
        cmd /c dir /R | findstr /C:":"
        
        Get-Content .\nothing_here -Stream hidden
______________________________________________________________________________________________________________________________________________________________________________________
### 30: "Fortune cookies" have been left around the system so that you won't find the hidden password... - ``` fortune_cookie ```

        Get-ChildItem -Path "C:\*fortune*" -Recurse
        
        cmd /c dir /R | findstr /C:":"
        
        Get-Content '.\The Fortune Cookie' -Stream none
______________________________________________________________________________________________________________________________________________________________________________________
### 31: There are plenty of phish in the C:\Users\CTF, but sometimes they're hidden in plain site. - ``` phi5hy ```

#### Goto C:\Users\CTF look for anything phishy related to site(WWW).

        Get-ChildItem -Force
        
        Get-Content -Force .\200
______________________________________________________________________________________________________________________________________________________________________________________
# |
# |
# |
# |
# |
# 07_windows_boot_process
______________________________________________________________________________________________________________________________________________________________________________________
### 1: What is the smallest addressable unit on a hard disk? - ``` Sector ```
______________________________________________________________________________________________________________________________________________________________________________________
### 2: What term describes a logical division of a single storage device? - ``` Partition ```
______________________________________________________________________________________________________________________________________________________________________________________
### 3: What term describes a formatted storage device that can span 1 or more partitions, has a single file system and is assigned a drive letter? - ``` Volume ```
______________________________________________________________________________________________________________________________________________________________________________________
### 4: What CLI disk partitioning tool is available in Windows to view and manipulate both partitions and volumes? - ``` Diskpart ```
______________________________________________________________________________________________________________________________________________________________________________________
### 5: Windows includes 4 critical Kernel-mode components. Which component is a matched pair with the kernel and obfuscates the hardware dependencies from the kernel? - ``` HAL ```
______________________________________________________________________________________________________________________________________________________________________________________
### 6: Windows includes 4 critical Kernel-mode components. Which component directs calls from a user-mode process to the kernel services? - ``` Executive ```
______________________________________________________________________________________________________________________________________________________________________________________
### 7: This provides an operating system with a software interface to a hardware device. - ``` Driver ```
______________________________________________________________________________________________________________________________________________________________________________________
### 8: What are the two firmware interfaces supported by modern computers and read in the Pre-boot phase of the Windows boot process? - ``` UEFI and BIOS ```
______________________________________________________________________________________________________________________________________________________________________________________
### 9: What is the name of the process that spawns SYSTEM? - ``` ntoskrnl.exe ```
______________________________________________________________________________________________________________________________________________________________________________________
### 10: In Windows what does the boot sector code load into memory? - ``` bootmgr and winload.exe ```
______________________________________________________________________________________________________________________________________________________________________________________
### 11: In Windows 10 what is the name of the boot manager? - ``` bootmgr ```
______________________________________________________________________________________________________________________________________________________________________________________
### 12: In Microsoft Vista and later the boot.ini file was replaced by what? - ``` BCD ```
______________________________________________________________________________________________________________________________________________________________________________________
### 13: What is the tamper-resistant processor mounted on the motherboard used to improve the security of your PC. It's used by services like BitLocker drive encryption and Windows Hello to securely create and store cryptographic keys, and to confirm that the operating system and firmware on your device are what they're supposed to be, and haven't been tampered with. - ``` TPM ```
______________________________________________________________________________________________________________________________________________________________________________________
### 14: During the Windows boot process, what starts BOOT_START device drivers and services with value of 0x0 in the registry key HKLM\SYSTEM\CurrentControlSet\Services? - ``` Winload.exe ```
______________________________________________________________________________________________________________________________________________________________________________________
### 15: During the Windows boot process, what starts SYSTEM_START device drivers and services with hex value of 0x1 in the registry key HKLM\SYSTEM\CurrentControlSet\Services? - ``` Ntoskrnl.exe ```
______________________________________________________________________________________________________________________________________________________________________________________
### 16: During the Windows boot process, services.exe starts device drivers and services on demand with what hex value in the registry key HKLM\SYSTEM\CurrentControlSet\Services? - ``` 0x2 ```
______________________________________________________________________________________________________________________________________________________________________________________
### 17: Starting in Windows Vista, what process spawns two additional instances (with identical names), used to initiate session 0 and session 1? - ``` smss.exe ```
______________________________________________________________________________________________________________________________________________________________________________________
### 18: Which Windows Vista user session is non-interactive, contains system services and processes and is isolated from the GDI (Graphical Device Interface). - ``` Session 0 ```
______________________________________________________________________________________________________________________________________________________________________________________
### 19: What is the boot process security feature available in UEFI systems, that only allows verified drivers to load? - ``` Secure Boot ```
______________________________________________________________________________________________________________________________________________________________________________________
### 20: To make booting faster, starting with Windows 8, the OS does a partial ________ of the kernel session at shutdown? - ``` Hibernation ```
______________________________________________________________________________________________________________________________________________________________________________________
### 21: What registry key is responsible for starting services on your machine during the boot process? Flag is the full registry path. - ``` HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNSERVICES ```
______________________________________________________________________________________________________________________________________________________________________________________
### 22: When a user logs on to a Windows host, authentication will either grant the user access to the local computer only (Local Logon) or the user will also be granted access to a Windows domain (Domain Logon). Which logon will the user be authenticated to via the Security Accounts Manager (SAM) database? - ``` Local Logon ```
______________________________________________________________________________________________________________________________________________________________________________________
### 23: What is the parent process of explorer.exe? - ``` userinit.exe ```
______________________________________________________________________________________________________________________________________________________________________________________
### 24: What is responsible for handling Windows SAS (secure attention sequence), user profile loading, assignment of security to user shell, and Windows station and desktop protection? - ``` winlogon.exe ```
______________________________________________________________________________________________________________________________________________________________________________________
### 25: What critical Windows process is initialized by wininit.exe, is responsible for creating the user's security access token and verifying user logon credentials? - ``` lsass.exe ```
______________________________________________________________________________________________________________________________________________________________________________________
### 26: What Microsoft recovery option overwrites the registry key HKLM\System\Select after every successful logon? - ``` Last known good configuration ```
______________________________________________________________________________________________________________________________________________________________________________________
### 27: What authentication protocol is the default for logging onto an Active Directory domain and features SSO (Single-Sign On), mutual authentication and primarily uses symmetric cryptography? - ``` Kerberos ```
______________________________________________________________________________________________________________________________________________________________________________________
### 28: In Kerberos the Active Directory controller serves as which major Kerberos component consisting of the Authentication Service (AS) and the Ticket Granting Service (TGS). - ``` Key Distribution Center ```
______________________________________________________________________________________________________________________________________________________________________________________
### 29: When would the following Windows registry keys, actions occur? HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify - ``` Logon ```
______________________________________________________________________________________________________________________________________________________________________________________
### 30: The Windows NT Operating System attempts to combine features and benefits of microkernel and monolithic kernel architectures, making it which type of kernel architecture? - ``` Hybrid ```
______________________________________________________________________________________________________________________________________________________________________________________
### 31: The Linux kernel is an example of what type of kernel architecture? - ``` Monolithic ```
______________________________________________________________________________________________________________________________________________________________________________________
### 32: Windows operating system name typically differs from its version number. Which Windows version includes Windows 7 and Windows Server 2008R2 and was the 1st version to ship with PowerShell? - ``` 6.1 ```
______________________________________________________________________________________________________________________________________________________________________________________
### 33: Which Windows version includes Windows Server 2016, 2019, 2022, Windows 10 & 11 and includes SMB 3.1.1 support? - ``` 10 ```
______________________________________________________________________________________________________________________________________________________________________________________
### 34: The CMD.EXE tool systeminfo included in Windows is very similar to msinfo32 and displays operating system configuration version information for a local or remote machine, including service pack levels. - ``` systeminfo | findstr /C:"OS Version" /C:"BIOS Version" ```

Craft a systeminfo command that only returns the below info:

OS Version: "System OS and Build #"

BIOS Version: "Your BIOS Ver"
______________________________________________________________________________________________________________________________________________________________________________________
### 35: What is the first process to spawn on Windows systems after the kernel loads? - ``` System ```
______________________________________________________________________________________________________________________________________________________________________________________
### 36: What is the Process ID (PID) of the first Windows process? - ``` 4 ```
______________________________________________________________________________________________________________________________________________________________________________________
### 37: What is the second boot process to spawn, that then spawns csrss in both session 0 and session 1? - ``` smss ```
______________________________________________________________________________________________________________________________________________________________________________________
### 38: What session ID do Windows services operate in? - ``` 0 ```
______________________________________________________________________________________________________________________________________________________________________________________
### 39: What process creates access tokens? - ``` lsass ```
______________________________________________________________________________________________________________________________________________________________________________________
### 40: What is the parent process to all svchosts? - ``` services ```
______________________________________________________________________________________________________________________________________________________________________________________
### 41: What process is waiting with high priority for the Secure Attention Sequence (SAS)? - ``` winlogon ```
______________________________________________________________________________________________________________________________________________________________________________________
### 42: What user space process spawns explorer, then dies? - ``` userinit ```
______________________________________________________________________________________________________________________________________________________________________________________
### 43: What is the name of the bootloader, with extension, we are using on all of the Windows machines in this environment? - ``` winload.exe ```
______________________________________________________________________________________________________________________________________________________________________________________
### 44: Based on the boot loader from Init_9, which firmware are we using (BIOS or UEFI) in our environment? - ``` BIOS ```
______________________________________________________________________________________________________________________________________________________________________________________
### 45: What file saves the memory state to the hard drive when going into hibernation? - ``` hiberfil.sys ```
______________________________________________________________________________________________________________________________________________________________________________________
### 46: What bootloader is responsible for restoring the system to its original state after hibernation? - ``` winresume.exe ```
______________________________________________________________________________________________________________________________________________________________________________________
### 47: The system is booting into safe mode. Identify the flag from the command-line output of the command used to diagnose boot issues. - ``` 1RF5Zgf9P ```

        bcdedit
______________________________________________________________________________________________________________________________________________________________________________________
### 48: The system is booting into safe mode. Correct that, and reboot into the desktop. The flag is on the desktop. - ``` 76Drp6hB ```

        bcdedit /deletevalue {default} safeboot
        
        shutdown /r
        
        shutdown -a    #run until it aborts the shutdown
______________________________________________________________________________________________________________________________________________________________________________________
### 49: Prevent the system restart using the command line, and then identify persistence mechanisms that are reverting the OS and boot loader configurations. - ``` ??? ```
______________________________________________________________________________________________________________________________________________________________________________________
### 50: Run PowerShell... if you can. Resolve PowerShell dependencies. - ``` ??? ```
______________________________________________________________________________________________________________________________________________________________________________________
### 51: Once you fix and launch PowerShell, the console is changed to a custom layout. Figure out what file is causing this, read the file, and inspect the file that it is referencing. - ``` ??? ```
______________________________________________________________________________________________________________________________________________________________________________________
# |
# |
# |
# |
# |
# 08_linux_boot_process
______________________________________________________________________________________________________________________________________________________________________________________
### 1:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 2:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 3:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 4:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 5:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 6:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 7:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 8:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 9:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 10:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 11:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 12:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 13:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 14:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 15:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 16:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 17:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 18:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 19:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 20:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 21:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 22:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 23:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 24:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
# |
# |
# |
# |
# |
# 09_windows_process_validity
______________________________________________________________________________________________________________________________________________________________________________________
### 1: What is the full path to folder used when Windows redirects 32 bit applications running on a 64bit system? - ``` C:\Windows\SysWOW64 ```

        reg query 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'

        Primer_Process(1) 
______________________________________________________________________________________________________________________________________________________________________________________
### 2: What Windows System Service starts the kernel and user mode subsystems? - ``` smss.exe ```
______________________________________________________________________________________________________________________________________________________________________________________
### 3: What Windows system process: - ``` lsass.exe ```

#### Runs in session 0
#### is responsible for enforcing the security policy on the system
#### Performs all logon functions
#### Handles password changes
#### Creates access tokens
#### Writes to the Windows Security Log
______________________________________________________________________________________________________________________________________________________________________________________
### 4: Which is spoolsv.exe? - ``` User-mode Service ```
______________________________________________________________________________________________________________________________________________________________________________________
### 5: Which service type is explorer.exe? - ``` Server-mode Service ```
______________________________________________________________________________________________________________________________________________________________________________________
### 6: During a network survey you observed a host running inetinfo.exe service. What type of server might you have found? - ``` IIS ```
______________________________________________________________________________________________________________________________________________________________________________________
### 7: During a reconnaissance mission you enumerated a host running the dns.exe service. Is this a user pc or a server? - ``` User PC ```
______________________________________________________________________________________________________________________________________________________________________________________
### 8: A host running firefox and office 365 is most likely what type of host? Server or Client - ``` Client ```
______________________________________________________________________________________________________________________________________________________________________________________
### 9: How does a User-Mode Service request resources? - ``` System Call ```
______________________________________________________________________________________________________________________________________________________________________________________
### 10: Passively copying currently running processes for comparison later is known as? - ``` Baselining ```
______________________________________________________________________________________________________________________________________________________________________________________
### 11: What can execute any part of a processes code, to include parts already being executed? - ``` Thread ```
______________________________________________________________________________________________________________________________________________________________________________________
### 12: Windows has how many process priority levels? - ``` 32 ```
______________________________________________________________________________________________________________________________________________________________________________________
### 13: What Sysinternals tool shows malware persistence locations in tabs within its GUI? - ``` Autoruns ```
______________________________________________________________________________________________________________________________________________________________________________________
### 14: What Sysinternals tool is used to investigate processes? - ``` Process Explorer ```
______________________________________________________________________________________________________________________________________________________________________________________
### 15: What Sysinternals tool can be used to investigate network connection attempts? - ``` TCPView ```
______________________________________________________________________________________________________________________________________________________________________________________
### 16: What Sysinternals tool can view permissions? - ``` AccessChk ```
______________________________________________________________________________________________________________________________________________________________________________________
### 17: What Sysinternals tool allows us to view and modify handles? - ``` Handle ```
______________________________________________________________________________________________________________________________________________________________________________________
### 18: What is the default Windows user directory for files downloaded from the internet? The flag is the folder name only. - ``` Downloads ```
______________________________________________________________________________________________________________________________________________________________________________________
### 19: What is the default Windows download directory that everyone has access to? The flag is the absolute path to the directory. - ``` C:\users\public\downloads ```
______________________________________________________________________________________________________________________________________________________________________________________
### 20: What Sysinternals tool shows service load order? - ``` LoadOrder ```
______________________________________________________________________________________________________________________________________________________________________________________
### 21: What is the service name of Windows Defender Firewall? - ``` MpsSvc ```
______________________________________________________________________________________________________________________________________________________________________________________
### 22: What SysInternals tool reports .dlls loaded into processes? - ``` ListDLLs ```
______________________________________________________________________________________________________________________________________________________________________________________
### 23: There is malware on the system that is named similarly to a legitimate Windows executable. There is a .dll in the folder that the malware runs from. The flag is the name of the .dll. - ``` libmingwex-0.dll ```
______________________________________________________________________________________________________________________________________________________________________________________
### 24: You notice that there is an annoying pop up happening regularly. Investigate the process causing it. The flag is the name of the executable. - ``` McAfeeFireTray.exe ```
______________________________________________________________________________________________________________________________________________________________________________________
### 25: Determine what is sending out a SYN_SENT message. The flag is the name of the executable. - ``` McAfeeFireTray.exe ```

> Get-Itemproperty 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1584283910-3275287195-1754958050-1005'
______________________________________________________________________________________________________________________________________________________________________________________
### 26: Malware uses names of legit processes to obfuscate itself. Give the flag located in Kerberos’ registry subkey. - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 27: There is malware named TotallyLegit. Find its binary location and there will be a file in that directory. Read the file. - ``` GwlkK3sa ```
______________________________________________________________________________________________________________________________________________________________________________________
### 28: Find the McAfeeFireTray.exe. There is a file in that directory. The flag is inside. - ``` StrongBad ```
______________________________________________________________________________________________________________________________________________________________________________________
### 29: What are the permissions for NT SERVICE\TrustedInstaller on spoolsv.exe? Copy the permissions from your shell. - ``` ??? ```
______________________________________________________________________________________________________________________________________________________________________________________
### 30: What is the PATH listed in the output when we find the handle for spoolsv.exe? - ``` ??? ```
______________________________________________________________________________________________________________________________________________________________________________________
### 31: In what Load Order Group is the Windows Firewall service? - ``` ??? ```
______________________________________________________________________________________________________________________________________________________________________________________
### 32: What is the first .dll associated with winlogon.exe? Provide the name of the .dll only, not the /absolute/path - ``` ??? ```
______________________________________________________________________________________________________________________________________________________________________________________
### 33: While examining the Windows Defender Firewall, what is the LogAllowedConnections setting set to, for the Public profile? - ``` ??? ```
______________________________________________________________________________________________________________________________________________________________________________________
### 34: A nonstandard port has been opened by possible malware on the system. Identify the port. - ``` ??? ```
______________________________________________________________________________________________________________________________________________________________________________________
### 35: Determine what mechanism opened the port from hidden_processes_7. The flag is the name of the file. - ``` ??? ```
______________________________________________________________________________________________________________________________________________________________________________________
### 36: Identify the flag from the file in hidden_processes_8. - ``` ??? ```
______________________________________________________________________________________________________________________________________________________________________________________
# |
# |
# |
# |
# |
# 10_windows_uac
______________________________________________________________________________________________________________________________________________________________________________________
### 1: What Sysinternals tool will allow you to view a file's manifest? - ``` sigcheck ```
______________________________________________________________________________________________________________________________________________________________________________________
### 2: What is the RequestedExecutionLevel for an application to run with the same permissions as the process that started it? - ``` asInvoker ```
______________________________________________________________________________________________________________________________________________________________________________________
### 3: What RequestedExecutionLevel will prompt the user for Administrator credentials if they're not a member of the Administrator's group? - ``` requireAdministrator ```
______________________________________________________________________________________________________________________________________________________________________________________
### 4: What registry key holds UAC values? - ``` HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System ```
______________________________________________________________________________________________________________________________________________________________________________________
### 5: The flag is the RequestedExecutionLevel of the schtasks.exe file. - ``` asInvoker ```
______________________________________________________________________________________________________________________________________________________________________________________
### 6: Determine which UAC subkey property shows whether UAC is enabled or not. The flag is the data value in that property. - ``` 0x1337 ```

> Reg Query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
______________________________________________________________________________________________________________________________________________________________________________________
### 7: Provide the name of the UAC [Registry subkey] property that determines what level UAC is set to for admin privileges (Example UAC levels: Default, Always, Notify). - ``` ConsentPromptBehaviorAdmin ```
______________________________________________________________________________________________________________________________________________________________________________________
### 8: Query the registry subkey where UAC settings are stored, and provide the flag. - ``` NiceJob ```
______________________________________________________________________________________________________________________________________________________________________________________
# |
# |
# |
# |
# |
# 11_windows_services
______________________________________________________________________________________________________________________________________________________________________________________
### 1: What command-line (cmd) command will show service information? - ``` sc query ```
______________________________________________________________________________________________________________________________________________________________________________________
### 2: What command-line (cmd) command will show all services, running or not running? - ``` sc query type=service state=all ```
______________________________________________________________________________________________________________________________________________________________________________________
### 3: What PowerShell command will list all services? - ``` Get-Service ```
______________________________________________________________________________________________________________________________________________________________________________________
### 4: What registry location holds all service data? - ``` HKLM\System\CurrentControlSet\Services ```
______________________________________________________________________________________________________________________________________________________________________________________
### 5: What registry subkey holds a service's .dll location? - ``` parameters ```
______________________________________________________________________________________________________________________________________________________________________________________
### 6: Services have a name and display name, which could be different. What is the service name of the only Totally-Legit service? - ``` Legit ```

> get-services
   
> get-service Totally-Legit | Format-list *
______________________________________________________________________________________________________________________________________________________________________________________
### 7: Figure out the SID of the only Totally-Legit service. - ``` 1182961511 ```

> sc showsid Legit
______________________________________________________________________________________________________________________________________________________________________________________
# |
# |
# |
# |
# |
# 12_linux_process_validity
______________________________________________________________________________________________________________________________________________________________________________________
### 1:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 2:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 3:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 4:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 5:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 6:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 7:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 8:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 9:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 10:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 11:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 12:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 13:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 14:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 15:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 16:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 17:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 18:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
# |
# |
# |
# |
# |
# 13_windows_auditing_and_logging
______________________________________________________________________________________________________________________________________________________________________________________
### 1: Logging, Auditing and Monitoring are often confused with each other but are distinctly different. Which term refers to real-time analysis and is often accomplished with a Security Event Information Management system (SIEM)? - ``` Monitoring ```
______________________________________________________________________________________________________________________________________________________________________________________
### 2: What term is most appropriate when referring to the process of reviewing log files or other records for specified period? - ``` Auditing ```
______________________________________________________________________________________________________________________________________________________________________________________
### 3: "Complete the following path to the Windows System Log which records system events e.g. startup and shutdown: %systemroot%\System32_______________ - ``` WinEvt\Logs\System.evtx ```
______________________________________________________________________________________________________________________________________________________________________________________
### 4: Which Windows log contains either success or failures and can be configured to record failed logon attempts? - ``` Security ```
______________________________________________________________________________________________________________________________________________________________________________________
### 5: "Which Windows account is the only account to have WRITE-APPEND access to Windows event logs?" - ``` SYSTEM ```
______________________________________________________________________________________________________________________________________________________________________________________
### 6: What is parsed in an NTFS object's security descriptor, by the Security Reference Monitor (SRM), to determine if an audit entry will be created in the Windows Security Log? - ``` SACL ```
______________________________________________________________________________________________________________________________________________________________________________________
### 7: Which registry key holds the audit policy configuration? - ``` HKLM\SECURITY\Policy\PolAdtEv ```
______________________________________________________________________________________________________________________________________________________________________________________
### 8: Which sysinternals tool is used to parse logs? - ``` PsLogList ```
______________________________________________________________________________________________________________________________________________________________________________________
### 9: What Sysinternals tool will allow you to read the SQLite3 database containing the web history of chrome? - ``` Strings ```
______________________________________________________________________________________________________________________________________________________________________________________
### 10: What is the registry location of recent docs for the current user? - ``` HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs ```
______________________________________________________________________________________________________________________________________________________________________________________
### 11: BAM settings are stored in different registry locations based on the version of Windows 10. What version of Windows 10 is workstation2 running? The answer is the 4 digit Windows 10 release (version) number. - ``` 1803 ```
______________________________________________________________________________________________________________________________________________________________________________________
### 12: Figure out the last access time of the hosts file. - ``` 08/14/2024 ```

> (Get-Item "C:\Windows\System32\drivers\etc\hosts").LastAccessTime
______________________________________________________________________________________________________________________________________________________________________________________
### 13: What is the literal path of the prefetch directory? - ``` C:\Windows\Prefetch ```
______________________________________________________________________________________________________________________________________________________________________________________
### 14: In the Recycle Bin, there is a file that contains the actual contents of the recycled file. What are the first two characters of this filename? - ``` $R ```
______________________________________________________________________________________________________________________________________________________________________________________
### 15: In the Recycle Bin, there is a file that contains the original filename, path, file size, and when the file was deleted. What are the first two characters of this filename? - ``` $I ```
______________________________________________________________________________________________________________________________________________________________________________________
### 16: What are the first 8 characters of the Globally Unique Identifier (GUID) used to list applications found in the UserAssist registry key (Windows 7 and later)? - ``` CEBFF5CD ```
______________________________________________________________________________________________________________________________________________________________________________________
### 17: What cipher method are UserAssist files encoded in? - ``` ROT13 ```
______________________________________________________________________________________________________________________________________________________________________________________
### 18: What main Windows log would show invalid login attempts? - ``` Security ```
______________________________________________________________________________________________________________________________________________________________________________________
### 19: What main Windows log will show whether Windows updates were applied recently? - ``` System ```
______________________________________________________________________________________________________________________________________________________________________________________
### 20: When reading logs, you may notice ... at the end of the line where the message is truncated. What format-table switch/argument will display the entire output? - ``` -wrap ```
______________________________________________________________________________________________________________________________________________________________________________________
### 21: Find the questionable website that a user browsed to (using Chrome), that appears to be malicious. *Note: There are more than one users on the box. - ``` https://www.exploit-db.com ```

> get-content 'C:\users\student\AppData\Local\Google\Chrome\User Data\Default\History'
______________________________________________________________________________________________________________________________________________________________________________________
### 22: There is a file that was recently opened that may contain PII. Get the flag from the contents of the file. - ``` Flag, Found A. ```

> reg query hkcu\software\microsoft\windows\currentversion\explorer\recentdocs

> get-item 'Registry::\HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.*' - [System.Text.Encoding]::Unicode.GetString((gp "REGISTRY::HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt")."6")
______________________________________________________________________________________________________________________________________________________________________________________
### 23: Enter the full path of the program that was run on this computer from an abnormal location. - ``` C:\Windows\Temp\bad_intentions.exe ```

> Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings\*
______________________________________________________________________________________________________________________________________________________________________________________
### 24: Enter the name of the questionable file in the prefetch folder. - ``` DARK_FORCES-8F2869FC.pf ```

> get-childitem -Path 'C:\Windows\Prefetch' -ErrorAction Continue
______________________________________________________________________________________________________________________________________________________________________________________
### 25: What is the creation time of the questionable file in the prefetch folder? - ``` 02/23/2022 ```
______________________________________________________________________________________________________________________________________________________________________________________
### 26: Recover the flag from the Recycle Bin. Enter the name of the recycle bin file that contained the contents of the flag, and the contents of the deleted file. Include the file extension in your answer. - ``` $RZDAQ4U.txt,DontTrashMeyo ```

> Get-Childitem 'C:\$RECYCLE.BIN' -Recurse -Verbose -Force | select FullName

> get-content 'C:\$RECYCLE.BIN\S-1-5-21-2881336348-3190591231-4063445930-1003\$RZDAQ4U.txt'
______________________________________________________________________________________________________________________________________________________________________________________
### 27: Find the file in the jump list location that might allow privilege escalation. - ``` ??? ```

> Get-ItemProperty -Path "C:\Users\<Username>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*" | Select-Object Name, LastWriteTime
______________________________________________________________________________________________________________________________________________________________________________________
### 28: Check event logs for a "flag" string. - ``` ??? ```
______________________________________________________________________________________________________________________________________________________________________________________
# |
# |
# |
# |
# |
# 14_linux_auditing_and_logging
______________________________________________________________________________________________________________________________________________________________________________________
### 1:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 2:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 3:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 4:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 5:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 6:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 7:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 8:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 9:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 10:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 11:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 12:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 13:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 14:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 15:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 16:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 17:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 18:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 19:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 20:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 21:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 22:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 23:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 24:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 25:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 26:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 27:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
# |
# |
# |
# |
# |
# 15_memory_analysis
______________________________________________________________________________________________________________________________________________________________________________________
### 1:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 2:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 3:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 4:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 5:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 6:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 7:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 8:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 9:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 10:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 11:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 12:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 13:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 14:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 15:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 16:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 17:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 18:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 19:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 20:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 21:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 22:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 23:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 24:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 25:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 26:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 27:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 28:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 29:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 30:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 31:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 32:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 33:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 34:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 35:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 36:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 37:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 38:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 39:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 40:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 41:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 42:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 43:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 44:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 45:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 46:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 47:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
### 48:  - ```  ```
______________________________________________________________________________________________________________________________________________________________________________________
# |
# |
# |
# |
# |
# 16_windows_active_directory_enumeration
______________________________________________________________________________________________________________________________________________________________________________________
### 1: What is the database that is used to connect users with network resources? - ``` Active Directory ```
______________________________________________________________________________________________________________________________________________________________________________________
### 2: What are all things that are in active directory stored as? - ``` Objects ```
______________________________________________________________________________________________________________________________________________________________________________________
### 3: What is the Active Directory component which contains formal definitions of every object class that can be created in an Active Directory forest? - ``` schema ```
______________________________________________________________________________________________________________________________________________________________________________________
### 4: What protocol is used when accessing and updating the Active Directory? - ``` LDAP ```
______________________________________________________________________________________________________________________________________________________________________________________
### 5: From an Offensive perspective, what type of account is usually the main target? - ``` Administrator ```
______________________________________________________________________________________________________________________________________________________________________________________
### 6: Task : If an account has been inactive for a substantial amount of time what should the adminstrators do to the account? - ``` Disable ```
______________________________________________________________________________________________________________________________________________________________________________________
### 7: What is the basic PowerShell cmdlet used to enumerate users? - ``` Get-ADUser ```
______________________________________________________________________________________________________________________________________________________________________________________
### 8: What is the suite of tools used in CLI to enumerate users across the network? - ``` DS ```
______________________________________________________________________________________________________________________________________________________________________________________
### 9: What is the domain portion of the following SID:S-1-5-21-1004336348-1177238915-682003330-1000 - ``` 21-1004336348-1177238915-682003330 ```
______________________________________________________________________________________________________________________________________________________________________________________
### 10: What PowerShell command will list domain groups? - ``` Get-ADGroup ```
______________________________________________________________________________________________________________________________________________________________________________________
### 11: What PowerShell command will list all users and their default properties? - ``` Get-ADUser -filter * ```
______________________________________________________________________________________________________________________________________________________________________________________
### 12: What PowerShell command will allow you to search Active Directory accounts for expired accounts without having to create a filter? - ``` Search-ADAccount ```
______________________________________________________________________________________________________________________________________________________________________________________
### 13: Find the expired accounts that aren't disabled. List the last names in Alphabetical Order, separated with a comma, and no space between. - ``` Krause,Page ```

```
Get-ADUser -Filter {Enabled -eq $true} -Properties AccountExpirationDate | Where-Object {$_.AccountExpirationDate -lt (get-date) -and $_.Enabled -ne $null} | select-object GivenName
```
______________________________________________________________________________________________________________________________________________________________________________________
### 14: Find the unprofessional email addresses. List the email's domain. - ``` ashleymadison.com ```

> get-aduser -filter * -properties EmailAddress | where-object {$_.emailaddress -notlike "*mail.mil"} | select-object EmailAddress
______________________________________________________________________________________________________________________________________________________________________________________
### 15: The flag is the unprofessionally-named file located somewhere on the Warrior Share. - ``` lulz.pdf ```

> get-childitem -force -recurse -erroraction SilentlyContinue | select Mode, LastWriteTime, Fullname
______________________________________________________________________________________________________________________________________________________________________________________
### 16: The flag is the name of the file, where in the file contents, someone is requesting modified access rights. - ``` 14287.pdf ```

> net use * "\\file-server\warrior share"
______________________________________________________________________________________________________________________________________________________________________________________
### 17: The flag is the name of the user who is requesting modified access rights. - ``` Karen.Nance ```

> Get-ADUser -Filter * -Properties telephoneNumber | where-object {$_.telephoneNumber -like "*336-6754"}
______________________________________________________________________________________________________________________________________________________________________________________
### 18: Find the accounts that contain unprofessional information in the description. - ``` Ibarra,Lee ```

> Get-ADUser -Filter * -Properties Description | select Description

> Get-ADUser -Filter * -Properties Description | where-object {$_.Description -notlike "*PLT Soldier"} | select-object Description

> Get-ADUser -Filter * -Properties Description | where-object {$_.Description -like "*description"}
______________________________________________________________________________________________________________________________________________________________________________________
### 19: Find the following three accounts: - ``` ??? ```

two accounts with passwords that never expire NOT andy.dwyer

one account that has its password stored using reversible encryption

List the last names in Alphabetical Order, comma-separated, no spaces. Do not list built-in accounts.
______________________________________________________________________________________________________________________________________________________________________________________
### 20: The flag is the name of the file containing PII on the Warrior Share. - ``` phone_matrix.xlsx ```

> get-childitem -force -recurse -erroraction SilentlyContinue | select Mode, LastWriteTime, Fullname
______________________________________________________________________________________________________________________________________________________________________________________
### 21: Find the short name of the domain in which this server is a part of. - ``` army ```

> get-addomaincontroller -filter *
______________________________________________________________________________________________________________________________________________________________________________________
### 22: What is the RID of the krbtgt account. - ``` 502 ```

> Get-ADUser -Filter * -Properties * | where-object {$_.name -like "*krbtgt"}
______________________________________________________________________________________________________________________________________________________________________________________
### 23: How many users are members of the Domain Admins group? - ``` ??? ```
______________________________________________________________________________________________________________________________________________________________________________________
### 24: How many total users are members of the Domain Admins group? - ``` ??? ```
______________________________________________________________________________________________________________________________________________________________________________________
### 25: Continue to follow the insider trail to find additional insider threats and their compromised mission. - ``` ??? ```
______________________________________________________________________________________________________________________________________________________________________________________
### 26: Continue to follow the insider trail to find additional insider threats and their compromised mission. - ``` ??? ```
______________________________________________________________________________________________________________________________________________________________________________________
### 27: Continue to follow the insider trail to find additional insider threats and their compromised mission. - ``` ??? ```
______________________________________________________________________________________________________________________________________________________________________________________
### 28: Continue to follow the insider trail to find additional insider threats and their compromised mission. This flag is a video link. - ``` ??? ```
______________________________________________________________________________________________________________________________________________________________________________________
