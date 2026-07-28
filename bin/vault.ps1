#Requires -Version 5.1
<#
.SYNOPSIS
  blind-vault Windows CLI backend.

.DESCRIPTION
  Stores secret values in Windows Credential Manager and keeps only pointer
  metadata in %USERPROFILE%\.blindvault\manifest.json. Secret values are never
  printed by this script. The `use` command injects a value into an external
  child process and redacts exact-value leaks from merged output.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

try {
    $utf8NoBom = New-Object Text.UTF8Encoding($false)
    if ([Console]::IsInputRedirected) {
        [Console]::InputEncoding = $utf8NoBom
    }
    if ([Console]::IsOutputRedirected) {
        [Console]::OutputEncoding = $utf8NoBom
    }
} catch {
    # Some embedded PowerShell hosts do not expose mutable console encodings.
}

$script:CredentialPrefix = 'BlindVault:v1:'
$script:UserProfileDir = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
$script:VaultDir = if ([string]::IsNullOrWhiteSpace($env:BLINDVAULT_DIR)) {
    Join-Path $script:UserProfileDir '.blindvault'
} else {
    [Environment]::ExpandEnvironmentVariables($env:BLINDVAULT_DIR)
}
$script:ManifestPath = Join-Path $script:VaultDir 'manifest.json'

function Stop-Vault {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [int]$ExitCode = 1
    )
    [Console]::Error.WriteLine("vault: $Message")
    exit $ExitCode
}

function Get-VaultExceptionMessage {
    param(
        [Parameter(Mandatory = $true)][Exception]$Exception
    )

    # PowerShell wraps exceptions thrown by Add-Type methods in one or more
    # MethodInvocationException layers. Report the native cause so failures
    # such as an unavailable logon vault are actionable instead of appearing
    # as a generic "Exception calling Write" message.
    $current = $Exception
    while ($null -ne $current.InnerException) {
        $current = $current.InnerException
    }

    $message = $current.Message
    if ($current -is [ComponentModel.Win32Exception]) {
        $message += " (Win32 error $($current.NativeErrorCode))"
    }
    return $message
}

function Show-Usage {
    @'
blind-vault for Windows - secrets your AI agent can use but never see

  vault init
  vault add <name> [flags]
      --service <label>       service name, e.g. OpenAI
      --account <id>          account/username pointer metadata
      --env <VAR>             injected environment variable (auto by default)
      --allow <s1,s2>         command targets allowed to consume this secret
      --note <text>           pointer-only note
      --from-stdin            read one line from standard input (automation)
  vault use <name> [--no-redact] -- <external-command> [args...]
  vault copy <name>           copy to clipboard and clear it after 30 seconds
  vault type <name> [flags]   type into the focused browser field (OS keystrokes)
      --account               type the stored account/ID first, then Tab
      --enter                 press Enter after the secret
      --delay <N>             seconds to switch focus, 0-60 (default 4)
  vault ls                    list pointers, never values
  vault ui                    open the local-only management dashboard
  vault rm <name>             remove from Credential Manager and manifest

Windows backend notes:
  - Values use Windows Credential Manager (Generic, local-machine persistence).
  - There is deliberately no `vault get` command.
  - `type` refuses to inject unless an allowed browser process is frontmost.
'@ | Write-Output
}

function Initialize-NativeCredentialApi {
    if ('BlindVault.WindowsCredentialStore' -as [type]) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace BlindVault
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct NativeCredential
    {
        public UInt32 Flags;
        public UInt32 Type;
        [MarshalAs(UnmanagedType.LPWStr)] public string TargetName;
        [MarshalAs(UnmanagedType.LPWStr)] public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public UInt32 CredentialBlobSize;
        public IntPtr CredentialBlob;
        public UInt32 Persist;
        public UInt32 AttributeCount;
        public IntPtr Attributes;
        [MarshalAs(UnmanagedType.LPWStr)] public string TargetAlias;
        [MarshalAs(UnmanagedType.LPWStr)] public string UserName;
    }

    public static class WindowsCredentialStore
    {
        private const UInt32 CredTypeGeneric = 1;
        private const UInt32 CredPersistLocalMachine = 2;
        private const int ErrorNotFound = 1168;
        public const int MaxCredentialBlobBytes = 5 * 512;

        [DllImport("Advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CredWrite(ref NativeCredential credential, UInt32 flags);

        [DllImport("Advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CredRead(string targetName, UInt32 type, UInt32 flags, out IntPtr credential);

        [DllImport("Advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CredDelete(string targetName, UInt32 type, UInt32 flags);

        [DllImport("Advapi32.dll")]
        private static extern void CredFree(IntPtr buffer);

        public static void Write(string targetName, string secret)
        {
            if (String.IsNullOrWhiteSpace(targetName))
                throw new ArgumentException("credential target is required", "targetName");
            if (String.IsNullOrEmpty(secret))
                throw new ArgumentException("empty value - nothing stored", "secret");

            byte[] valueBytes = Encoding.UTF8.GetBytes(secret);
            if (valueBytes.Length > MaxCredentialBlobBytes)
            {
                Array.Clear(valueBytes, 0, valueBytes.Length);
                throw new ArgumentException(
                    "secret is " + valueBytes.Length + " UTF-8 bytes; Windows Credential Manager allows at most " +
                    MaxCredentialBlobBytes + " bytes");
            }

            GCHandle pinned = default(GCHandle);
            try
            {
                pinned = GCHandle.Alloc(valueBytes, GCHandleType.Pinned);
                NativeCredential credential = new NativeCredential
                {
                    Flags = 0,
                    Type = CredTypeGeneric,
                    TargetName = targetName,
                    Comment = null,
                    CredentialBlobSize = (UInt32)valueBytes.Length,
                    CredentialBlob = pinned.AddrOfPinnedObject(),
                    Persist = CredPersistLocalMachine,
                    AttributeCount = 0,
                    Attributes = IntPtr.Zero,
                    TargetAlias = null,
                    UserName = null
                };

                if (!CredWrite(ref credential, 0))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Credential Manager write failed");
            }
            finally
            {
                Array.Clear(valueBytes, 0, valueBytes.Length);
                if (pinned.IsAllocated)
                    pinned.Free();
            }
        }

        public static string Read(string targetName)
        {
            IntPtr pointer;
            if (!CredRead(targetName, CredTypeGeneric, 0, out pointer))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Credential Manager lookup failed");

            try
            {
                NativeCredential credential =
                    (NativeCredential)Marshal.PtrToStructure(pointer, typeof(NativeCredential));
                byte[] valueBytes = new byte[credential.CredentialBlobSize];
                try
                {
                    if (valueBytes.Length > 0)
                        Marshal.Copy(credential.CredentialBlob, valueBytes, 0, valueBytes.Length);
                    return Encoding.UTF8.GetString(valueBytes);
                }
                finally
                {
                    Array.Clear(valueBytes, 0, valueBytes.Length);
                }
            }
            finally
            {
                CredFree(pointer);
            }
        }

        public static bool Delete(string targetName)
        {
            if (CredDelete(targetName, CredTypeGeneric, 0))
                return true;

            int error = Marshal.GetLastWin32Error();
            if (error == ErrorNotFound)
                return false;
            throw new Win32Exception(error, "Credential Manager delete failed");
        }
    }

    public static class AtomicFile
    {
        private const UInt32 MoveFileReplaceExisting = 0x1;
        private const UInt32 MoveFileWriteThrough = 0x8;

        [DllImport("Kernel32.dll", EntryPoint = "MoveFileExW", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool MoveFileEx(string existingFileName, string newFileName, UInt32 flags);

        public static void Replace(string sourcePath, string destinationPath)
        {
            if (!MoveFileEx(sourcePath, destinationPath, MoveFileReplaceExisting | MoveFileWriteThrough))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "atomic manifest replace failed");
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct KeyboardInput
    {
        public UInt16 VirtualKey;
        public UInt16 ScanCode;
        public UInt32 Flags;
        public UInt32 Time;
        public UIntPtr ExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MouseInput
    {
        public Int32 X;
        public Int32 Y;
        public UInt32 MouseData;
        public UInt32 Flags;
        public UInt32 Time;
        public UIntPtr ExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct HardwareInput
    {
        public UInt32 Message;
        public UInt16 ParameterLow;
        public UInt16 ParameterHigh;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct InputUnion
    {
        [FieldOffset(0)] public MouseInput Mouse;
        [FieldOffset(0)] public KeyboardInput Keyboard;
        [FieldOffset(0)] public HardwareInput Hardware;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NativeInput
    {
        public UInt32 Type;
        public InputUnion Data;
    }

    public static class SecureTyper
    {
        private const UInt32 InputKeyboard = 1;
        private const UInt32 KeyEventKeyUp = 0x0002;
        private const UInt32 KeyEventUnicode = 0x0004;
        private const UInt16 VirtualKeyTab = 0x09;
        private const UInt16 VirtualKeyReturn = 0x0D;

        [DllImport("User32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("User32.dll", SetLastError = true)]
        private static extern UInt32 GetWindowThreadProcessId(IntPtr window, out UInt32 processId);

        [DllImport("User32.dll", SetLastError = true)]
        private static extern UInt32 SendInput(UInt32 inputCount, NativeInput[] inputs, Int32 inputSize);

        [DllImport("User32.dll")]
        private static extern Int16 GetAsyncKeyState(Int32 virtualKey);

        [DllImport("User32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsIconic(IntPtr window);

        public static IntPtr ForegroundWindow()
        {
            IntPtr window = GetForegroundWindow();
            if (window == IntPtr.Zero)
                throw new InvalidOperationException("no foreground window is available; nothing was typed");
            return window;
        }

        public static string ForegroundProcessName(IntPtr expectedWindow)
        {
            if (expectedWindow == IntPtr.Zero || GetForegroundWindow() != expectedWindow)
                throw new InvalidOperationException("the foreground window changed; nothing was typed");

            UInt32 processId;
            if (GetWindowThreadProcessId(expectedWindow, out processId) == 0 || processId == 0)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "foreground process lookup failed");

            using (Process process = Process.GetProcessById((Int32)processId))
                return process.ProcessName;
        }

        private static void AppendUnicode(List<NativeInput> inputs, string value)
        {
            foreach (char character in value)
            {
                inputs.Add(KeyboardEvent(0, character, KeyEventUnicode));
                inputs.Add(KeyboardEvent(0, character, KeyEventUnicode | KeyEventKeyUp));
            }
        }

        private static void AppendVirtualKey(List<NativeInput> inputs, UInt16 virtualKey)
        {
            inputs.Add(KeyboardEvent(virtualKey, (char)0, 0));
            inputs.Add(KeyboardEvent(virtualKey, (char)0, KeyEventKeyUp));
        }

        private static NativeInput KeyboardEvent(UInt16 virtualKey, char scanCode, UInt32 flags)
        {
            NativeInput input = new NativeInput();
            input.Type = InputKeyboard;
            input.Data.Keyboard = new KeyboardInput
            {
                VirtualKey = virtualKey,
                ScanCode = scanCode,
                Flags = flags,
                Time = 0,
                ExtraInfo = UIntPtr.Zero
            };
            return input;
        }

        private static bool HasPressedInput()
        {
            // Mouse buttons plus Shift, Ctrl, Alt, and both Windows keys.
            Int32[] keys = new Int32[] { 0x01, 0x02, 0x04, 0x05, 0x06, 0x10, 0x11, 0x12, 0x5B, 0x5C };
            foreach (Int32 key in keys)
                if ((GetAsyncKeyState(key) & unchecked((Int16)0x8000)) != 0)
                    return true;
            return false;
        }

        private static void EnsureStableForeground(IntPtr expectedWindow)
        {
            if (expectedWindow == IntPtr.Zero || GetForegroundWindow() != expectedWindow)
                throw new InvalidOperationException("the foreground window changed; nothing was typed");
            if (IsIconic(expectedWindow))
                throw new InvalidOperationException("the target window is minimized; nothing was typed");
            if (HasPressedInput())
                throw new InvalidOperationException("release the mouse and modifier keys, then retry; nothing was typed");

            Thread.Sleep(80);
            if (GetForegroundWindow() != expectedWindow)
                throw new InvalidOperationException("the foreground window changed; nothing was typed");
            if (HasPressedInput())
                throw new InvalidOperationException("input focus is not stable; nothing was typed");
        }

        private static void SendBatch(IntPtr expectedWindow, List<NativeInput> inputs)
        {
            EnsureStableForeground(expectedWindow);
            NativeInput[] batch = inputs.ToArray();
            try
            {
                UInt32 sent = SendInput((UInt32)batch.Length, batch, Marshal.SizeOf(typeof(NativeInput)));
                if (sent != batch.Length)
                {
                    Int32 error = Marshal.GetLastWin32Error();
                    if (sent > 0)
                        throw new Win32Exception(
                            error,
                            "partial keyboard injection: some text may have been typed; blind-vault will not retry");
                    throw new Win32Exception(
                        error,
                        "Windows blocked keyboard injection; the target may be elevated");
                }
            }
            finally
            {
                Array.Clear(batch, 0, batch.Length);
                inputs.Clear();
            }
        }

        public static Int32 InputStructureSize()
        {
            return Marshal.SizeOf(typeof(NativeInput));
        }

        public static void SendAccountAndTab(IntPtr expectedWindow, string account)
        {
            if (String.IsNullOrEmpty(account))
                throw new ArgumentException("empty account cannot be typed", "account");
            List<NativeInput> inputs = new List<NativeInput>();
            AppendUnicode(inputs, account);
            AppendVirtualKey(inputs, VirtualKeyTab);
            SendBatch(expectedWindow, inputs);
        }

        public static void SendSecret(IntPtr expectedWindow, string secret, bool pressEnter)
        {
            if (String.IsNullOrEmpty(secret))
                throw new ArgumentException("empty secret cannot be typed", "secret");
            List<NativeInput> inputs = new List<NativeInput>();
            AppendUnicode(inputs, secret);
            if (pressEnter)
                AppendVirtualKey(inputs, VirtualKeyReturn);
            SendBatch(expectedWindow, inputs);
        }
    }
}
'@
}

function Assert-Windows {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        Stop-Vault 'the PowerShell backend requires native Windows (not Linux/WSL)'
    }
}

function Assert-Name {
    param([Parameter(Mandatory = $true)][string]$Name)
    if ($Name -notmatch '^[A-Za-z0-9._-]+$') {
        Stop-Vault 'name must use only letters, digits, dot, dash, or underscore'
    }
}

function Get-CredentialTarget {
    param([Parameter(Mandatory = $true)][string]$Name)
    # Credential Manager target names are case-insensitive. Canonicalizing here
    # keeps Foo/foo from becoming two manifest pointers to one credential.
    return $script:CredentialPrefix + $Name.ToLowerInvariant()
}

function Get-FocusedFieldState {
    try {
        if (-not ('System.Windows.Automation.AutomationElement' -as [type])) {
            Add-Type -AssemblyName UIAutomationClient
        }
        $element = [System.Windows.Automation.AutomationElement]::FocusedElement
        if ($null -eq $element) {
            return [pscustomobject]@{ IsEdit = $false; IsPassword = $false }
        }
        $controlType = $element.GetCurrentPropertyValue(
            [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
            $true
        )
        $passwordValue = $element.GetCurrentPropertyValue(
            [System.Windows.Automation.AutomationElement]::IsPasswordProperty,
            $true
        )
        $isEdit = $null -ne $controlType -and
            $controlType.Id -eq [System.Windows.Automation.ControlType]::Edit.Id
        return [pscustomobject]@{
            IsEdit     = $isEdit
            IsPassword = $passwordValue -is [bool] -and [bool]$passwordValue
        }
    } catch {
        return [pscustomobject]@{ IsEdit = $false; IsPassword = $false }
    }
}

function Test-ControlCharacter {
    param([AllowEmptyString()][string]$Value)
    return -not [string]::IsNullOrEmpty($Value) -and
        [Regex]::IsMatch($Value, '[\x00-\x1F\x7F]')
}

function Initialize-Vault {
    if (-not (Test-Path -LiteralPath $script:VaultDir)) {
        New-Item -ItemType Directory -Path $script:VaultDir -Force | Out-Null
    }
    if (-not (Test-Path -LiteralPath $script:ManifestPath)) {
        Save-Manifest ([pscustomobject]@{ secrets = @() })
    }
    Write-Output "vault ready at $script:VaultDir (pointers only - values live in Windows Credential Manager)"
}

function Get-Manifest {
    if (-not (Test-Path -LiteralPath $script:ManifestPath)) {
        Stop-Vault 'not initialized - run: vault init'
    }

    $raw = [IO.File]::ReadAllText($script:ManifestPath, [Text.Encoding]::UTF8)
    try {
        $manifest = $raw | ConvertFrom-Json
    } catch {
        Stop-Vault "invalid manifest JSON at $script:ManifestPath"
    }

    if ($null -eq $manifest.PSObject.Properties['secrets']) {
        Stop-Vault "invalid manifest: missing 'secrets' array"
    }
    $manifest.secrets = @($manifest.secrets)
    return $manifest
}

function Save-Manifest {
    param([Parameter(Mandatory = $true)]$Manifest)

    if (-not (Test-Path -LiteralPath $script:VaultDir)) {
        New-Item -ItemType Directory -Path $script:VaultDir -Force | Out-Null
    }

    $json = $Manifest | ConvertTo-Json -Depth 8
    $tempPath = Join-Path $script:VaultDir ('.manifest.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $utf8NoBom = New-Object Text.UTF8Encoding($false)
    try {
        [IO.File]::WriteAllText($tempPath, $json + [Environment]::NewLine, $utf8NoBom)
        Initialize-NativeCredentialApi
        [BlindVault.AtomicFile]::Replace($tempPath, $script:ManifestPath)
    } finally {
        if (Test-Path -LiteralPath $tempPath) {
            Remove-Item -LiteralPath $tempPath -Force
        }
    }
}

function Find-Pointer {
    param(
        [Parameter(Mandatory = $true)]$Manifest,
        [Parameter(Mandatory = $true)][string]$Name
    )
    return @($Manifest.secrets | Where-Object {
        ([string]$_.name).Equals($Name, [StringComparison]::OrdinalIgnoreCase)
    }) | Select-Object -First 1
}

function Read-SecretValue {
    param(
        [switch]$FromStdin,
        [string]$Name = 'secret'
    )

    if ($FromStdin) {
        $value = [Console]::In.ReadLine()
        if ($null -eq $value) {
            Stop-Vault 'no value received on standard input'
        }
        return $value
    }

    return Show-SecretDialog $Name
}

function Show-SecretDialog {
    param([Parameter(Mandatory = $true)][string]$Name)

    if (-not [Environment]::UserInteractive) {
        Stop-Vault 'no interactive Windows desktop is available; use --from-stdin for automation'
    }

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne [Threading.ApartmentState]::STA) {
        Stop-Vault 'the secure input dialog requires an STA PowerShell session; run via bin\vault.cmd'
    }

    $form = New-Object Windows.Forms.Form
    $title = New-Object Windows.Forms.Label
    $description = New-Object Windows.Forms.Label
    $secretBox = New-Object Windows.Forms.TextBox
    $saveButton = New-Object Windows.Forms.Button
    $cancelButton = New-Object Windows.Forms.Button
    $accepted = $false
    $value = $null

    try {
        $form.Text = 'Blind Vault'
        $form.ClientSize = New-Object Drawing.Size(460, 210)
        $form.FormBorderStyle = [Windows.Forms.FormBorderStyle]::FixedDialog
        $form.StartPosition = [Windows.Forms.FormStartPosition]::CenterScreen
        $form.MaximizeBox = $false
        $form.MinimizeBox = $false
        $form.ShowIcon = $false
        $form.ShowInTaskbar = $false
        $form.TopMost = $false
        $form.AutoScaleMode = [Windows.Forms.AutoScaleMode]::Dpi
        $form.BackColor = [Drawing.Color]::FromArgb(246, 247, 249)

        $title.AutoSize = $true
        $title.Location = New-Object Drawing.Point(24, 22)
        $title.Font = New-Object Drawing.Font('Segoe UI Semibold', 13)
        $title.Text = "Store '$Name'"

        $description.AutoSize = $false
        $description.Location = New-Object Drawing.Point(26, 56)
        $description.Size = New-Object Drawing.Size(408, 42)
        $description.Font = New-Object Drawing.Font('Segoe UI', 9)
        $description.ForeColor = [Drawing.Color]::FromArgb(75, 82, 92)
        $description.Text = "Paste the value below. It is sent directly to Windows Credential Manager and is never printed."

        $secretBox.Location = New-Object Drawing.Point(28, 104)
        $secretBox.Size = New-Object Drawing.Size(404, 28)
        $secretBox.Font = New-Object Drawing.Font('Segoe UI', 10)
        $secretBox.UseSystemPasswordChar = $true
        $secretBox.AccessibleName = 'Secret value'

        $saveButton.Location = New-Object Drawing.Point(258, 154)
        $saveButton.Size = New-Object Drawing.Size(84, 32)
        $saveButton.Text = 'Save'
        $saveButton.Add_Click({
            $candidate = $secretBox.Text
            if ([string]::IsNullOrEmpty($candidate)) {
                [void][Windows.Forms.MessageBox]::Show(
                    $form,
                    'Enter a non-empty value.',
                    'Blind Vault',
                    [Windows.Forms.MessageBoxButtons]::OK,
                    [Windows.Forms.MessageBoxIcon]::Warning
                )
                return
            }
            if ([Text.Encoding]::UTF8.GetByteCount($candidate) -gt 2560) {
                [void][Windows.Forms.MessageBox]::Show(
                    $form,
                    'The UTF-8 value exceeds the 2,560-byte Windows Credential Manager limit.',
                    'Blind Vault',
                    [Windows.Forms.MessageBoxButtons]::OK,
                    [Windows.Forms.MessageBoxIcon]::Warning
                )
                return
            }
            $form.Tag = $candidate
            $form.DialogResult = [Windows.Forms.DialogResult]::OK
            $form.Close()
        })

        $cancelButton.Location = New-Object Drawing.Point(348, 154)
        $cancelButton.Size = New-Object Drawing.Size(84, 32)
        $cancelButton.Text = 'Cancel'
        $cancelButton.DialogResult = [Windows.Forms.DialogResult]::Cancel

        $form.AcceptButton = $saveButton
        $form.CancelButton = $cancelButton
        [void]$form.Controls.AddRange(@($title, $description, $secretBox, $saveButton, $cancelButton))
        $form.Add_Shown({
            $form.Activate()
            $secretBox.Select()
        })

        if ($form.ShowDialog() -eq [Windows.Forms.DialogResult]::OK) {
            $value = [string]$form.Tag
            $accepted = $true
        }
    } finally {
        $secretBox.Clear()
        $form.Dispose()
    }

    if (-not $accepted) {
        Stop-Vault 'cancelled' 130
    }
    return $value
}

function Invoke-Add {
    param([string[]]$Tokens)
    if ($Tokens.Count -lt 1) {
        Stop-Vault 'usage: vault add <name> [flags]'
    }

    $name = [string]$Tokens[0]
    Assert-Name $name
    $service = ''
    $account = [Environment]::UserName
    $envName = ''
    $allow = ''
    $note = ''
    $fromStdin = $false

    $index = 1
    while ($index -lt $Tokens.Count) {
        $flag = [string]$Tokens[$index]
        switch ($flag) {
            '--from-stdin' {
                $fromStdin = $true
                $index++
                continue
            }
            { $_ -in @('--service', '--account', '--env', '--allow', '--note') } {
                if ($index + 1 -ge $Tokens.Count) {
                    Stop-Vault "missing value for $flag"
                }
                $optionValue = [string]$Tokens[$index + 1]
                switch ($flag) {
                    '--service' { $service = $optionValue }
                    '--account' { $account = $optionValue }
                    '--env'     { $envName = $optionValue }
                    '--allow'   { $allow = $optionValue }
                    '--note'    { $note = $optionValue }
                }
                $index += 2
                continue
            }
            default {
                Stop-Vault "unknown flag: $flag"
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($envName)) {
        $envName = $name.ToUpperInvariant().Replace('-', '_').Replace('.', '_')
    }
    if ($envName -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') {
        Stop-Vault "invalid environment variable name: $envName"
    }

    $manifest = Get-Manifest
    $existing = Find-Pointer $manifest $name
    if ($null -ne $existing -and -not ([string]$existing.name).Equals($name, [StringComparison]::Ordinal)) {
        Stop-Vault "'$name' conflicts with existing pointer '$($existing.name)' because Windows credential names are case-insensitive"
    }

    $value = Read-SecretValue -FromStdin:$fromStdin -Name $name
    if ([string]::IsNullOrEmpty($value)) {
        Stop-Vault 'empty value - nothing stored'
    }

    try {
        Initialize-NativeCredentialApi
        [BlindVault.WindowsCredentialStore]::Write((Get-CredentialTarget $name), $value)
    } finally {
        $value = $null
    }

    $allowedTargets = @($allow.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $newPointer = [pscustomobject][ordered]@{
        name        = $name
        service     = $service.Trim()
        account     = $account.Trim()
        env         = $envName
        allowed_for = $allowedTargets
        note        = $note.Trim()
        created     = [DateTime]::Today.ToString('yyyy-MM-dd')
        last_used   = $null
        backend     = 'windows-credential-manager'
    }
    $otherPointers = @($manifest.secrets | Where-Object {
        -not ([string]$_.name).Equals($name, [StringComparison]::OrdinalIgnoreCase)
    })
    $manifest.secrets = @($otherPointers + $newPointer | Sort-Object name)
    Save-Manifest $manifest
    Write-Output "stored '$name' in Windows Credential Manager (injects as `$$envName). The value was not printed."
}

function Test-ScopeTarget {
    param(
        [Parameter(Mandatory = $true)][string]$CommandLine,
        [Parameter(Mandatory = $true)][string[]]$AllowedTargets
    )

    foreach ($target in $AllowedTargets) {
        if ([string]::IsNullOrWhiteSpace($target)) {
            continue
        }
        $pattern = '(^|[^A-Za-z0-9_-])' + [Regex]::Escape($target) + '([^A-Za-z0-9_.-]|$)'
        if ([Regex]::IsMatch($CommandLine, $pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Invoke-Use {
    param([string[]]$Tokens)
    if ($Tokens.Count -lt 3) {
        Stop-Vault 'usage: vault use <name> [--no-redact] -- <external-command> [args...]'
    }

    $name = [string]$Tokens[0]
    Assert-Name $name
    $noRedact = ($env:BLINDVAULT_NO_REDACT -eq '1')
    $separator = -1
    for ($i = 1; $i -lt $Tokens.Count; $i++) {
        if ($Tokens[$i] -eq '--') {
            $separator = $i
            break
        }
        if ($Tokens[$i] -eq '--no-redact') {
            $noRedact = $true
        } else {
            Stop-Vault "unknown option before --: $($Tokens[$i])"
        }
    }
    if ($separator -lt 0 -or $separator + 1 -ge $Tokens.Count) {
        Stop-Vault 'usage: vault use <name> [--no-redact] -- <external-command> [args...]'
    }

    $commandTokens = @($Tokens[($separator + 1)..($Tokens.Count - 1)])
    $executable = [string]$commandTokens[0]
    $executableArgs = if ($commandTokens.Count -gt 1) {
        @($commandTokens[1..($commandTokens.Count - 1)])
    } else {
        @()
    }

    try {
        $resolvedCommand = Get-Command $executable -CommandType Application -ErrorAction Stop
    } catch {
        Stop-Vault "external command not found: $executable"
    }

    $manifest = Get-Manifest
    $pointer = Find-Pointer $manifest $name
    if ($null -eq $pointer) {
        Stop-Vault "no secret named '$name' - see: vault ls"
    }

    $allowedTargets = @($pointer.allowed_for)
    $commandLine = [string]::Join(' ', $commandTokens)
    if ($allowedTargets.Count -gt 0 -and
        $env:BLINDVAULT_FORCE -ne '1' -and
        -not (Test-ScopeTarget $commandLine $allowedTargets)) {
        $scopeMessage = ("SCOPE BLOCK: '$name' is scoped to [{0}] but the command mentions none of them.`n" +
            'If this is intentional, a HUMAN can set BLINDVAULT_FORCE=1. Agents must stop and ask.') -f
            ([string]::Join(',', $allowedTargets))
        Stop-Vault $scopeMessage
    }

    Initialize-NativeCredentialApi
    $secret = [BlindVault.WindowsCredentialStore]::Read((Get-CredentialTarget $name))
    $envName = [string]$pointer.env
    $oldValue = [Environment]::GetEnvironmentVariable($envName, [EnvironmentVariableTarget]::Process)

    $pointer.last_used = [DateTime]::Today.ToString('yyyy-MM-dd')
    Save-Manifest $manifest

    $exitCode = 1
    try {
        [Environment]::SetEnvironmentVariable($envName, $secret, [EnvironmentVariableTarget]::Process)
        $global:LASTEXITCODE = 0
        if ($noRedact) {
            & $resolvedCommand.Source @executableArgs
        } else {
            $replacement = "[REDACTED:$name]"
            & $resolvedCommand.Source @executableArgs 2>&1 | ForEach-Object {
                $text = [string]$_
                if (-not [string]::IsNullOrEmpty($secret)) {
                    $text = $text.Replace($secret, $replacement)
                }
                [Console]::Out.WriteLine($text)
            }
        }
        $exitCode = $global:LASTEXITCODE
    } finally {
        [Environment]::SetEnvironmentVariable($envName, $oldValue, [EnvironmentVariableTarget]::Process)
        $secret = $null
    }
    exit $exitCode
}

function Invoke-List {
    $manifest = Get-Manifest
    $pointers = @($manifest.secrets)
    if ($pointers.Count -eq 0) {
        Write-Output 'vault is empty - add one: vault add <name> --service <svc> --allow <domain>'
        return
    }

    $rows = $pointers | Sort-Object name | ForEach-Object {
        [pscustomobject][ordered]@{
            NAME       = $_.name
            ENV        = $_.env
            SERVICE    = if ([string]::IsNullOrWhiteSpace([string]$_.service)) { '-' } else { $_.service }
            'ALLOWED FOR' = if (@($_.allowed_for).Count -eq 0) { '-' } else { [string]::Join(',', @($_.allowed_for)) }
            'LAST USED' = if ($null -eq $_.last_used) { 'never' } else { $_.last_used }
        }
    }
    ($rows | Format-Table -AutoSize | Out-String -Width 240).TrimEnd() | Write-Output
}

function Invoke-Copy {
    param([string[]]$Tokens)
    if ($Tokens.Count -ne 1) {
        Stop-Vault 'usage: vault copy <name>'
    }
    $name = [string]$Tokens[0]
    Assert-Name $name
    $manifest = Get-Manifest
    if ($null -eq (Find-Pointer $manifest $name)) {
        Stop-Vault "no secret named '$name'"
    }

    Initialize-NativeCredentialApi
    $secret = [BlindVault.WindowsCredentialStore]::Read((Get-CredentialTarget $name))
    try {
        Set-Clipboard -Value $secret
    } finally {
        $secret = $null
    }

    $clearCommand = "Start-Sleep -Seconds 30; Set-Clipboard -Value ''"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($clearCommand))
    $powerShellExe = (Get-Process -Id $PID).Path
    Start-Process -FilePath $powerShellExe -WindowStyle Hidden -ArgumentList @(
        '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-EncodedCommand', $encoded
    ) | Out-Null
    Write-Output "'$name' copied to clipboard - auto-clears in 30 seconds"
}

function Invoke-Type {
    param([string[]]$Tokens)
    if ($Tokens.Count -lt 1) {
        Stop-Vault 'usage: vault type <name> [--account] [--enter] [--delay N]'
    }

    $name = [string]$Tokens[0]
    Assert-Name $name
    $withAccount = $false
    $pressEnter = $false
    $delaySeconds = 4

    $index = 1
    while ($index -lt $Tokens.Count) {
        $flag = [string]$Tokens[$index]
        switch ($flag) {
            '--account' {
                $withAccount = $true
                $index++
                continue
            }
            '--enter' {
                $pressEnter = $true
                $index++
                continue
            }
            '--delay' {
                if ($index + 1 -ge $Tokens.Count) {
                    Stop-Vault 'missing value for --delay'
                }
                $parsedDelay = 0
                if (-not [int]::TryParse([string]$Tokens[$index + 1], [ref]$parsedDelay) -or
                    $parsedDelay -lt 0 -or $parsedDelay -gt 60) {
                    Stop-Vault '--delay must be a whole number from 0 through 60'
                }
                $delaySeconds = $parsedDelay
                $index += 2
                continue
            }
            default {
                Stop-Vault "unknown flag: $flag"
            }
        }
    }

    $manifest = Get-Manifest
    $pointer = Find-Pointer $manifest $name
    if ($null -eq $pointer) {
        Stop-Vault "no secret named '$name'"
    }
    $account = [string]$pointer.account
    if ($withAccount -and [string]::IsNullOrWhiteSpace($account)) {
        Stop-Vault "'$name' has no account/ID stored"
    }
    if ($withAccount -and (Test-ControlCharacter $account)) {
        Stop-Vault "'$name' account/ID contains a control character and cannot be typed safely"
    }

    Write-Output "typing in ${delaySeconds}s - focus the target browser field now..."
    if ($delaySeconds -gt 0) {
        Start-Sleep -Seconds $delaySeconds
    }

    Initialize-NativeCredentialApi
    $window = [BlindVault.SecureTyper]::ForegroundWindow()
    $frontProcess = [BlindVault.SecureTyper]::ForegroundProcessName($window)
    $defaultApps = 'msedge,chrome,chromium,firefox,brave,brave-browser,vivaldi,opera,opera_gx,arc,whale'
    $configuredApps = if ([string]::IsNullOrWhiteSpace($env:BLINDVAULT_TYPE_APPS)) {
        $defaultApps
    } else {
        $env:BLINDVAULT_TYPE_APPS
    }
    $allowedApps = @($configuredApps.Split(',') | ForEach-Object {
        ([string]$_).Trim() -replace '(?i)\.exe$', ''
    } | Where-Object { $_ })
    $isAllowed = @($allowedApps | Where-Object {
        ([string]$_).Equals($frontProcess, [StringComparison]::OrdinalIgnoreCase)
    }).Count -gt 0
    if (-not $isAllowed) {
        Stop-Vault "frontmost process is '$frontProcess', not an allowed browser - aborted, nothing typed. (override: BLINDVAULT_TYPE_APPS)"
    }

    if ($withAccount) {
        $initialField = Get-FocusedFieldState
        if (-not $initialField.IsEdit -or $initialField.IsPassword) {
            Stop-Vault 'focus a non-password username/account field before using --account; nothing typed'
        }
        [BlindVault.SecureTyper]::SendAccountAndTab($window, $account)

        $passwordFieldReady = $false
        for ($attempt = 0; $attempt -lt 12; $attempt++) {
            Start-Sleep -Milliseconds 100
            [void][BlindVault.SecureTyper]::ForegroundProcessName($window)
            $nextField = Get-FocusedFieldState
            if ($nextField.IsEdit -and $nextField.IsPassword) {
                $passwordFieldReady = $true
                break
            }
        }
        if (-not $passwordFieldReady) {
            Stop-Vault 'Tab did not reach a browser password field; the account may have been typed, but the secret was not read or typed'
        }
    } else {
        $passwordField = Get-FocusedFieldState
        if (-not $passwordField.IsEdit -or -not $passwordField.IsPassword) {
            Stop-Vault 'focus a browser password field before typing a secret; nothing typed'
        }
    }

    $secret = $null
    try {
        $secret = [BlindVault.WindowsCredentialStore]::Read((Get-CredentialTarget $name))
        if (Test-ControlCharacter $secret) {
            Stop-Vault 'the secret contains a control character and cannot be typed safely'
        }
        [BlindVault.SecureTyper]::SendSecret($window, $secret, $pressEnter)
    } finally {
        $secret = $null
    }

    $pointer.last_used = [DateTime]::Today.ToString('yyyy-MM-dd')
    Save-Manifest $manifest
    Write-Output "typed into '$frontProcess'. The value was never printed or copied to the clipboard."
}

function Invoke-UI {
    $uiScript = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\ui\vault_ui.py'))
    if (-not (Test-Path -LiteralPath $uiScript)) {
        Stop-Vault "UI server is missing: $uiScript"
    }

    $pythonPath = $null
    $pythonArgs = @()
    $pythonOverride = [Environment]::GetEnvironmentVariable('BLINDVAULT_PYTHON')
    if (-not [string]::IsNullOrWhiteSpace($pythonOverride)) {
        if (Test-Path -LiteralPath $pythonOverride) {
            $pythonPath = (Resolve-Path -LiteralPath $pythonOverride).Path
        } else {
            try {
                $pythonPath = @(Get-Command $pythonOverride -CommandType Application -All -ErrorAction Stop |
                    Where-Object { $_.Source -notlike '*\WindowsApps\*' } |
                    Select-Object -First 1).Source
            } catch {
                Stop-Vault "BLINDVAULT_PYTHON was not found: $pythonOverride"
            }
        }
    } else {
        $python = @(Get-Command python.exe -CommandType Application -All -ErrorAction SilentlyContinue |
            Where-Object { $_.Source -notlike '*\WindowsApps\*' } |
            Select-Object -First 1)
        if ($python.Count -eq 1) {
            $pythonPath = $python[0].Source
        } else {
            $launcher = @(Get-Command py.exe -CommandType Application -All -ErrorAction SilentlyContinue |
                Where-Object { $_.Source -notlike '*\WindowsApps\*' } |
                Select-Object -First 1)
            if ($launcher.Count -eq 1) {
                $pythonPath = $launcher[0].Source
                $pythonArgs = @('-3')
            }
        }
    }
    if ([string]::IsNullOrWhiteSpace($pythonPath)) {
        Stop-Vault 'Python 3 was not found; install Python or set BLINDVAULT_PYTHON'
    }

    $global:LASTEXITCODE = 0
    & $pythonPath @pythonArgs $uiScript
    exit $global:LASTEXITCODE
}

function Invoke-Remove {
    param([string[]]$Tokens)
    if ($Tokens.Count -ne 1) {
        Stop-Vault 'usage: vault rm <name>'
    }
    $name = [string]$Tokens[0]
    Assert-Name $name
    $manifest = Get-Manifest
    $pointer = Find-Pointer $manifest $name
    if ($null -eq $pointer) {
        Stop-Vault "no secret named '$name'"
    }

    Initialize-NativeCredentialApi
    [void][BlindVault.WindowsCredentialStore]::Delete((Get-CredentialTarget $name))
    $manifest.secrets = @($manifest.secrets | Where-Object {
        -not ([string]$_.name).Equals($name, [StringComparison]::OrdinalIgnoreCase)
    })
    Save-Manifest $manifest
    Write-Output "removed '$name' (Windows Credential Manager + manifest)"
}

Assert-Windows

$commandName = if ($args.Count -gt 0) { [string]$args[0] } else { '' }
$remaining = if ($args.Count -gt 1) { @($args[1..($args.Count - 1)]) } else { @() }

try {
    switch ($commandName.ToLowerInvariant()) {
        'init'   { Initialize-Vault }
        'add'    { Invoke-Add $remaining }
        'use'    { Invoke-Use $remaining }
        'copy'   { Invoke-Copy $remaining }
        'type'   { Invoke-Type $remaining }
        'ls'     { Invoke-List }
        'list'   { Invoke-List }
        'ui'     { Invoke-UI }
        'rm'     { Invoke-Remove $remaining }
        'remove' { Invoke-Remove $remaining }
        'delete' { Invoke-Remove $remaining }
        'help'   { Show-Usage }
        '-h'     { Show-Usage }
        '--help' { Show-Usage }
        ''       { Show-Usage }
        default  { Stop-Vault "unknown command: $commandName (see: vault help)" }
    }
} catch {
    Stop-Vault (Get-VaultExceptionMessage $_.Exception)
}
