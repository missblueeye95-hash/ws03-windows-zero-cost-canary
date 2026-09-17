$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($env:GITHUB_ACTIONS -ne 'true') {
    throw 'This probe is only valid inside GitHub Actions.'
}
if ($env:RUNNER_OS -ne 'Windows') {
    throw 'This probe requires a Windows runner.'
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

$nativeSource = @"
using System;
using System.Runtime.InteropServices;
public static class Ws03Native {
    [DllImport("user32.dll", SetLastError=true)] public static extern IntPtr OpenInputDesktop(uint dwFlags, bool fInherit, uint dwDesiredAccess);
    [DllImport("user32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)] public static extern bool CloseDesktop(IntPtr hDesktop);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public InputUnion U; }
    [StructLayout(LayoutKind.Explicit)] public struct InputUnion {
        [FieldOffset(0)] public MOUSEINPUT mi;
        [FieldOffset(0)] public KEYBDINPUT ki;
        [FieldOffset(0)] public HARDWAREINPUT hi;
    }
    [StructLayout(LayoutKind.Sequential)] public struct MOUSEINPUT { public int dx; public int dy; public uint mouseData; public uint dwFlags; public uint time; public UIntPtr dwExtraInfo; }
    [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public UIntPtr dwExtraInfo; }
    [StructLayout(LayoutKind.Sequential)] public struct HARDWAREINPUT { public uint uMsg; public ushort wParamL; public ushort wParamH; }
    [DllImport("user32.dll", SetLastError=true)] public static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);
    public static uint SendUnicodeText(string text) {
        const uint INPUT_KEYBOARD = 1, KEYEVENTF_KEYUP = 0x0002, KEYEVENTF_UNICODE = 0x0004;
        INPUT[] inputs = new INPUT[text.Length * 2];
        for (int i = 0; i < text.Length; i++) {
            inputs[i * 2].type = INPUT_KEYBOARD; inputs[i * 2].U.ki.wScan = text[i]; inputs[i * 2].U.ki.dwFlags = KEYEVENTF_UNICODE;
            inputs[i * 2 + 1].type = INPUT_KEYBOARD; inputs[i * 2 + 1].U.ki.wScan = text[i]; inputs[i * 2 + 1].U.ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
        }
        return SendInput((uint)inputs.Length, inputs, Marshal.SizeOf(typeof(INPUT)));
    }
}
"@
Add-Type -TypeDefinition $nativeSource -Language CSharp

$probeTitle = 'WS03-GHA-UI-PROBE-' + [Guid]::NewGuid().ToString('N')
$marker = 'WS03_INPUT_' + [Guid]::NewGuid().ToString('N')
$uiScriptPath = Join-Path $env:RUNNER_TEMP 'ws03-ui-probe.ps1'
$uiScriptLines = @(
    'Add-Type -AssemblyName System.Windows.Forms',
    'Add-Type -AssemblyName System.Drawing',
    '$form = New-Object System.Windows.Forms.Form',
    '$form.Text = $env:WS03_PROBE_TITLE',
    '$form.Width = 640',
    '$form.Height = 240',
    '$form.StartPosition = ''CenterScreen''',
    '$form.TopMost = $true',
    '$textBox = New-Object System.Windows.Forms.TextBox',
    '$textBox.Name = ''Ws03ProbeInput''',
    '$textBox.Width = 560',
    '$textBox.Location = New-Object System.Drawing.Point(30, 70)',
    '$form.Controls.Add($textBox)',
    '$form.Add_Shown({ $textBox.Focus() })',
    '[System.Windows.Forms.Application]::Run($form)'
)
Set-Content -Path $uiScriptPath -Value ($uiScriptLines -join [Environment]::NewLine) -Encoding UTF8

$env:WS03_PROBE_TITLE = $probeTitle
$uiProcess = $null
$inputDesktopOpened = $false
$uiaWindowFound = $false
$uiaTextBoxFound = $false
$screenshotCaptured = $false
$screenshotNonUniform = $false
$screenshotSha256 = $null
$screenshotWidth = 0
$screenshotHeight = 0
$sendInputExpected = $marker.Length * 2
$sendInputSent = 0
$sendInputEffective = $false
$probeErrorClass = $null
$probeErrorStage = $null

try {
    $desktopAccess = 0x0001 -bor 0x0080 -bor 0x0100
    $desktop = [Ws03Native]::OpenInputDesktop(0, $false, $desktopAccess)
    if ($desktop -ne [IntPtr]::Zero) {
        $inputDesktopOpened = $true
        [void][Ws03Native]::CloseDesktop($desktop)
    }

    $uiProcess = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList @('-NoLogo', '-NoProfile', '-Sta', '-File', $uiScriptPath) -PassThru
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    $window = $null
    do {
        Start-Sleep -Milliseconds 250
        $condition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $uiProcess.Id)
        $window = [System.Windows.Automation.AutomationElement]::RootElement.FindFirst([System.Windows.Automation.TreeScope]::Children, $condition)
    } while ($null -eq $window -and [DateTime]::UtcNow -lt $deadline)

    if ($null -ne $window) {
        $uiaWindowFound = $true
        $editCondition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Edit)
        $edit = $window.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $editCondition)
        if ($null -ne $edit) { $uiaTextBoxFound = $true }

        $screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
        if ($screen.Width -gt 0 -and $screen.Height -gt 0) {
            $bitmap = New-Object System.Drawing.Bitmap($screen.Width, $screen.Height)
            $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
            try { $graphics.CopyFromScreen($screen.Left, $screen.Top, 0, 0, $screen.Size, [System.Drawing.CopyPixelOperation]::SourceCopy) }
            finally { $graphics.Dispose() }
            try {
                $stream = New-Object System.IO.MemoryStream
                try {
                    $bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
                    $bytes = $stream.ToArray()
                    $screenshotCaptured = $bytes.Length -gt 100
                    $screenshotSha256 = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
                    $screenshotWidth = $bitmap.Width
                    $screenshotHeight = $bitmap.Height
                    $points = @(@(0,0), @([Math]::Max(0,$bitmap.Width-1),0), @(0,[Math]::Max(0,$bitmap.Height-1)), @([Math]::Max(0,$bitmap.Width-1),[Math]::Max(0,$bitmap.Height-1)), @([int]($bitmap.Width/2),[int]($bitmap.Height/2)))
                    $argb = @($points | ForEach-Object { $bitmap.GetPixel($_[0], $_[1]).ToArgb() } | Select-Object -Unique)
                    $screenshotNonUniform = $argb.Count -gt 1
                } finally { $stream.Dispose() }
            } finally { $bitmap.Dispose() }
        }

        if ($uiaTextBoxFound) {
            $procNow = Get-Process -Id $uiProcess.Id
            [void][Ws03Native]::SetForegroundWindow($procNow.MainWindowHandle)
            Start-Sleep -Milliseconds 500
            $sendInputSent = [int][Ws03Native]::SendUnicodeText($marker)
            Start-Sleep -Milliseconds 750
            $valueAvailable = [bool]$edit.GetCurrentPropertyValue([System.Windows.Automation.AutomationElement]::IsValuePatternAvailableProperty)
            if ($valueAvailable) {
                $valuePattern = [System.Windows.Automation.ValuePattern]$edit.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
                $sendInputEffective = $valuePattern.Current.Value -eq $marker
            }
        }
    }
} catch {
    $probeErrorClass = $_.Exception.GetType().Name
    $probeErrorStage = $_.InvocationInfo.MyCommand.Name
} finally {
    if ($null -ne $uiProcess) {
        try {
            if (-not $uiProcess.HasExited) {
                [void]$uiProcess.CloseMainWindow()
                if (-not $uiProcess.WaitForExit(1500)) { $uiProcess.Kill($true); $uiProcess.WaitForExit() }
            }
        } catch { try { $uiProcess.Kill($true) } catch { } }
    }
    Remove-Item -Force -ErrorAction SilentlyContinue $uiScriptPath
}

$sessionId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
$freshVm = $env:WS03_FRESH_VM -eq 'true'
$publicRepo = $env:WS03_REPO_VISIBILITY -eq 'public'
$standardRunner = $env:WS03_STANDARD_RUNNER -eq 'true'
$runnerLabel = $env:WS03_RUNNER_LABEL
$physicalDesktopAccepted = ($freshVm -and $publicRepo -and $standardRunner -and $runnerLabel -eq 'windows-2025' -and [Environment]::UserInteractive -and $sessionId -gt 0 -and $inputDesktopOpened -and $uiaWindowFound -and $uiaTextBoxFound -and $screenshotCaptured -and $screenshotNonUniform -and $sendInputSent -eq $sendInputExpected -and $sendInputEffective)

$result = [ordered]@{
    schema_version = 1
    provider_candidate = 'github_actions_standard_public_windows'
    observed_at_utc = [DateTime]::UtcNow.ToString('o')
    github_actions = $true
    repository_visibility = $env:WS03_REPO_VISIBILITY
    standard_runner = $standardRunner
    runner_label = $runnerLabel
    runner_os = $env:RUNNER_OS
    fresh_vm = $freshVm
    powershell_version = $PSVersionTable.PSVersion.ToString()
    user_interactive = [Environment]::UserInteractive
    session_id = $sessionId
    input_desktop_opened = $inputDesktopOpened
    uia_window_found = $uiaWindowFound
    uia_textbox_found = $uiaTextBoxFound
    screenshot_captured = $screenshotCaptured
    screenshot_non_uniform = $screenshotNonUniform
    screenshot_width = $screenshotWidth
    screenshot_height = $screenshotHeight
    screenshot_sha256 = $screenshotSha256
    sendinput_events_expected = $sendInputExpected
    sendinput_events_sent = $sendInputSent
    sendinput_effective = $sendInputEffective
    physical_desktop_accepted = $physicalDesktopAccepted
    probe_error_class = $probeErrorClass
    probe_error_stage = $probeErrorStage
}

$json = $result | ConvertTo-Json -Compress -Depth 4
Write-Output "WS03_CANARY_JSON=$json"
if (-not $physicalDesktopAccepted) {
    Write-Output 'WS03_WINDOWS_GUI_STRONG=NOT_ACCEPTED'
    exit 3
}
Write-Output 'WS03_WINDOWS_GUI_STRONG=ACCEPTED'
