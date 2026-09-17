$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'WS03 v2 requires Windows.'
}
if ($env:GITHUB_ACTIONS -ne 'true') {
    throw 'WS03 v2 is only valid inside GitHub Actions.'
}
if ($env:RUNNER_OS -ne 'Windows') {
    throw 'WS03 v2 requires a Windows runner.'
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

$nativeSource = @"
using System;
using System.Runtime.InteropServices;
public static class Ws03NativeV2 {
    [DllImport("user32.dll", SetLastError=true)] public static extern IntPtr OpenInputDesktop(uint dwFlags, bool fInherit, uint dwDesiredAccess);
    [DllImport("user32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)] public static extern bool CloseDesktop(IntPtr hDesktop);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] public static extern bool GetPhysicalCursorPos(out POINT lpPoint);
    [DllImport("user32.dll", SetLastError=true)] public static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);

    [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X; public int Y; }
    [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public InputUnion U; }
    [StructLayout(LayoutKind.Explicit)] public struct InputUnion {
        [FieldOffset(0)] public MOUSEINPUT mi;
        [FieldOffset(0)] public KEYBDINPUT ki;
        [FieldOffset(0)] public HARDWAREINPUT hi;
    }
    [StructLayout(LayoutKind.Sequential)] public struct MOUSEINPUT {
        public int dx; public int dy; public uint mouseData; public uint dwFlags; public uint time; public UIntPtr dwExtraInfo;
    }
    [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT {
        public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public UIntPtr dwExtraInfo;
    }
    [StructLayout(LayoutKind.Sequential)] public struct HARDWAREINPUT { public uint uMsg; public ushort wParamL; public ushort wParamH; }

    public static uint SendUnicodeText(string text) {
        const uint INPUT_KEYBOARD = 1;
        const uint KEYEVENTF_KEYUP = 0x0002;
        const uint KEYEVENTF_UNICODE = 0x0004;
        INPUT[] inputs = new INPUT[text.Length * 2];
        for (int i = 0; i < text.Length; i++) {
            inputs[i * 2].type = INPUT_KEYBOARD;
            inputs[i * 2].U.ki.wScan = text[i];
            inputs[i * 2].U.ki.dwFlags = KEYEVENTF_UNICODE;
            inputs[i * 2 + 1].type = INPUT_KEYBOARD;
            inputs[i * 2 + 1].U.ki.wScan = text[i];
            inputs[i * 2 + 1].U.ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
        }
        return SendInput((uint)inputs.Length, inputs, Marshal.SizeOf(typeof(INPUT)));
    }

    private static int NormalizeAbsolute(int value, int origin, int span) {
        if (span <= 1) throw new ArgumentOutOfRangeException("span");
        double scaled = (value - origin) * 65535.0 / (span - 1);
        return (int)Math.Max(0, Math.Min(65535, Math.Round(scaled)));
    }

    public static uint SendAbsoluteMouseMove(int x, int y, int virtualLeft, int virtualTop, int virtualWidth, int virtualHeight) {
        const uint INPUT_MOUSE = 0;
        const uint MOUSEEVENTF_MOVE = 0x0001;
        const uint MOUSEEVENTF_VIRTUALDESK = 0x4000;
        const uint MOUSEEVENTF_ABSOLUTE = 0x8000;
        int nx = NormalizeAbsolute(x, virtualLeft, virtualWidth);
        int ny = NormalizeAbsolute(y, virtualTop, virtualHeight);
        INPUT[] inputs = new INPUT[1];
        inputs[0].type = INPUT_MOUSE;
        inputs[0].U.mi.dx = nx;
        inputs[0].U.mi.dy = ny;
        inputs[0].U.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
        return SendInput(1, inputs, Marshal.SizeOf(typeof(INPUT)));
    }

    public static uint SendLeftButton(bool down) {
        const uint INPUT_MOUSE = 0;
        const uint MOUSEEVENTF_LEFTDOWN = 0x0002;
        const uint MOUSEEVENTF_LEFTUP = 0x0004;
        INPUT[] inputs = new INPUT[1];
        inputs[0].type = INPUT_MOUSE;
        inputs[0].U.mi.dwFlags = down ? MOUSEEVENTF_LEFTDOWN : MOUSEEVENTF_LEFTUP;
        return SendInput(1, inputs, Marshal.SizeOf(typeof(INPUT)));
    }
}
"@
Add-Type -TypeDefinition $nativeSource -Language CSharp
$dpiAwarenessRequestReturned = [bool][Ws03NativeV2]::SetProcessDPIAware()

function Get-ValuePatternText([System.Windows.Automation.AutomationElement]$Element) {
    $available = [bool]$Element.GetCurrentPropertyValue([System.Windows.Automation.AutomationElement]::IsValuePatternAvailableProperty)
    if (-not $available) { return $null }
    $pattern = [System.Windows.Automation.ValuePattern]$Element.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
    return $pattern.Current.Value
}

function Set-ValuePatternText([System.Windows.Automation.AutomationElement]$Element, [string]$Value) {
    $available = [bool]$Element.GetCurrentPropertyValue([System.Windows.Automation.AutomationElement]::IsValuePatternAvailableProperty)
    if (-not $available) { throw 'Required ValuePattern is unavailable.' }
    $pattern = [System.Windows.Automation.ValuePattern]$Element.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
    $pattern.SetValue($Value)
}

$probeId = [Guid]::NewGuid().ToString('N')
$probeTitle = 'WS03-GITHUB-WINDOWS-V2-' + $probeId
$keyMarker = 'WS03_KEY_' + [Guid]::NewGuid().ToString('N')
$clickMarker = 'WS03_CLICK_' + [Guid]::NewGuid().ToString('N')
$expectedReceipt = $clickMarker + '|1'
$uiScriptPath = Join-Path $env:RUNNER_TEMP ('ws03-v2-ui-' + $probeId + '.ps1')
$receiptPath = Join-Path $env:RUNNER_TEMP ('ws03-v2-receipt-' + $probeId + '.txt')

$uiScript = @'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$form = New-Object System.Windows.Forms.Form
$form.Text = $env:WS03_V2_TITLE
$form.Width = 640
$form.Height = 300
$form.StartPosition = 'CenterScreen'
$form.TopMost = $true

$input = New-Object System.Windows.Forms.TextBox
$input.Name = 'Ws03Input'
$input.AccessibleName = 'Ws03Input'
$input.Left = 30
$input.Top = 35
$input.Width = 560

$button = New-Object System.Windows.Forms.Button
$button.Name = 'Ws03PhysicalClick'
$button.AccessibleName = 'Ws03PhysicalClick'
$button.Text = 'Physical click probe'
$button.Left = 30
$button.Top = 90
$button.Width = 190
$button.Height = 40

$receipt = New-Object System.Windows.Forms.TextBox
$receipt.Name = 'Ws03Receipt'
$receipt.AccessibleName = 'Ws03Receipt'
$receipt.Left = 30
$receipt.Top = 160
$receipt.Width = 560
$receipt.ReadOnly = $true
$receipt.Text = 'EMPTY'

$script:clickCount = 0
$button.Add_Click({
    $script:clickCount++
    $proof = $input.Text + '|' + $script:clickCount
    $receipt.Text = $proof
    [System.IO.File]::WriteAllText($env:WS03_V2_RECEIPT_PATH, $proof)
})

$form.Controls.AddRange(@($input, $button, $receipt))
$form.Add_Shown({ $input.Focus() })
[System.Windows.Forms.Application]::Run($form)
'@
Set-Content -LiteralPath $uiScriptPath -Value $uiScript -Encoding UTF8

$env:WS03_V2_TITLE = $probeTitle
$env:WS03_V2_RECEIPT_PATH = $receiptPath
$uiProcess = $null
$inputDesktopOpened = $false
$uiaWindowFound = $false
$uiaInputFound = $false
$uiaButtonFound = $false
$uiaReceiptFound = $false
$screenshotCaptured = $false
$screenshotNonUniform = $false
$screenshotSha256 = $null
$screenshotBytes = 0
$screenshotWidth = 0
$screenshotHeight = 0
$keyboardEventsExpected = $keyMarker.Length * 2
$keyboardEventsSent = 0
$keyboardEffective = $false
$mouseEventsExpected = 3
$mouseEventsSent = 0
$mouseMoveEventsSent = 0
$mouseButtonDownEventsSent = 0
$mouseButtonUpEventsSent = 0
$mouseEffectiveUiReceipt = $false
$mouseEffectiveFileReceipt = $false
$buttonCenterX = $null
$buttonCenterY = $null
$buttonClickablePointFound = $false
$buttonClickX = $null
$buttonClickY = $null
$buttonEnabled = $false
$buttonOffscreen = $true
$foregroundWindowRequested = $false
$physicalCursorReadback = $false
$physicalCursorX = $null
$physicalCursorY = $null
$cursorMoveEffective = $false
$cursorHitAutomationId = $null
$cursorHitButton = $false
$probeErrorClass = $null
$probeErrorStage = $null

try {
    $desktopAccess = 0x0001 -bor 0x0080 -bor 0x0100
    $desktop = [Ws03NativeV2]::OpenInputDesktop(0, $false, $desktopAccess)
    if ($desktop -ne [IntPtr]::Zero) {
        $inputDesktopOpened = $true
        [void][Ws03NativeV2]::CloseDesktop($desktop)
    }

    $uiProcess = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList @('-NoLogo','-NoProfile','-Sta','-File',$uiScriptPath) -PassThru
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    $window = $null
    do {
        Start-Sleep -Milliseconds 250
        $processCondition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $uiProcess.Id)
        $window = [System.Windows.Automation.AutomationElement]::RootElement.FindFirst([System.Windows.Automation.TreeScope]::Children, $processCondition)
    } while ($null -eq $window -and [DateTime]::UtcNow -lt $deadline)

    if ($null -ne $window) {
        $uiaWindowFound = $true
        $idProperty = [System.Windows.Automation.AutomationElement]::AutomationIdProperty
        $inputElement = $window.FindFirst([System.Windows.Automation.TreeScope]::Descendants, (New-Object System.Windows.Automation.PropertyCondition($idProperty, 'Ws03Input')))
        $buttonElement = $window.FindFirst([System.Windows.Automation.TreeScope]::Descendants, (New-Object System.Windows.Automation.PropertyCondition($idProperty, 'Ws03PhysicalClick')))
        $receiptElement = $window.FindFirst([System.Windows.Automation.TreeScope]::Descendants, (New-Object System.Windows.Automation.PropertyCondition($idProperty, 'Ws03Receipt')))
        $uiaInputFound = $null -ne $inputElement
        $uiaButtonFound = $null -ne $buttonElement
        $uiaReceiptFound = $null -ne $receiptElement

        $screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
        if ($screen.Width -gt 1 -and $screen.Height -gt 1) {
            $bitmap = New-Object System.Drawing.Bitmap($screen.Width, $screen.Height)
            $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
            try {
                $graphics.CopyFromScreen($screen.Left, $screen.Top, 0, 0, $screen.Size, [System.Drawing.CopyPixelOperation]::SourceCopy)
            } finally {
                $graphics.Dispose()
            }
            try {
                $stream = New-Object System.IO.MemoryStream
                try {
                    $bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
                    $bytes = $stream.ToArray()
                    $screenshotBytes = $bytes.Length
                    $screenshotCaptured = $screenshotBytes -gt 100
                    $screenshotSha256 = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
                    $screenshotWidth = $bitmap.Width
                    $screenshotHeight = $bitmap.Height
                    $colors = New-Object 'System.Collections.Generic.HashSet[int]'
                    foreach ($iy in 0..4) {
                        foreach ($ix in 0..4) {
                            $px = [Math]::Min($bitmap.Width - 1, [Math]::Max(0, [int](($bitmap.Width - 1) * $ix / 4)))
                            $py = [Math]::Min($bitmap.Height - 1, [Math]::Max(0, [int](($bitmap.Height - 1) * $iy / 4)))
                            [void]$colors.Add($bitmap.GetPixel($px, $py).ToArgb())
                        }
                    }
                    $screenshotNonUniform = $colors.Count -gt 1
                } finally {
                    $stream.Dispose()
                }
            } finally {
                $bitmap.Dispose()
            }
        }

        if ($uiaInputFound -and $uiaButtonFound -and $uiaReceiptFound) {
            $procNow = Get-Process -Id $uiProcess.Id
            [void][Ws03NativeV2]::SetForegroundWindow($procNow.MainWindowHandle)
            $window.SetFocus()
            $inputElement.SetFocus()
            Set-ValuePatternText $inputElement ''
            Start-Sleep -Milliseconds 350
            $keyboardEventsSent = [int][Ws03NativeV2]::SendUnicodeText($keyMarker)
            Start-Sleep -Milliseconds 500
            $keyboardEffective = (Get-ValuePatternText $inputElement) -eq $keyMarker

            Set-ValuePatternText $inputElement $clickMarker
            Remove-Item -LiteralPath $receiptPath -Force -ErrorAction SilentlyContinue
            $foregroundWindowRequested = [bool][Ws03NativeV2]::SetForegroundWindow($procNow.MainWindowHandle)
            $window.SetFocus()
            Start-Sleep -Milliseconds 350

            $buttonEnabled = [bool]$buttonElement.Current.IsEnabled
            $buttonOffscreen = [bool]$buttonElement.Current.IsOffscreen
            $rect = $buttonElement.Current.BoundingRectangle
            if (-not $rect.IsEmpty -and $rect.Width -ge 5 -and $rect.Height -ge 5) {
                $buttonCenterX = [int][Math]::Round($rect.Left + ($rect.Width / 2.0))
                $buttonCenterY = [int][Math]::Round($rect.Top + ($rect.Height / 2.0))
            }

            $clickPoint = [System.Windows.Point]::new()
            $buttonClickablePointFound = [bool]$buttonElement.TryGetClickablePoint([ref]$clickPoint)
            if ($buttonClickablePointFound -and $buttonEnabled -and -not $buttonOffscreen) {
                $buttonClickX = [int][Math]::Round($clickPoint.X)
                $buttonClickY = [int][Math]::Round($clickPoint.Y)

                $mouseMoveEventsSent = [int][Ws03NativeV2]::SendAbsoluteMouseMove(
                    $buttonClickX,
                    $buttonClickY,
                    $screen.Left,
                    $screen.Top,
                    $screen.Width,
                    $screen.Height
                )
                Start-Sleep -Milliseconds 500

                $cursorPoint = [Ws03NativeV2+POINT]::new()
                $physicalCursorReadback = [bool][Ws03NativeV2]::GetPhysicalCursorPos([ref]$cursorPoint)
                if ($physicalCursorReadback) {
                    $physicalCursorX = $cursorPoint.X
                    $physicalCursorY = $cursorPoint.Y
                    $cursorMoveEffective = (
                        [Math]::Abs($physicalCursorX - $buttonClickX) -le 2 -and
                        [Math]::Abs($physicalCursorY - $buttonClickY) -le 2
                    )
                    $cursorElement = [System.Windows.Automation.AutomationElement]::FromPoint(
                        [System.Windows.Point]::new([double]$physicalCursorX, [double]$physicalCursorY)
                    )
                    if ($null -ne $cursorElement) {
                        $cursorHitAutomationId = $cursorElement.Current.AutomationId
                        $cursorHitButton = $cursorHitAutomationId -eq 'Ws03PhysicalClick'
                    }
                }

                if ($mouseMoveEventsSent -eq 1 -and $cursorMoveEffective -and $cursorHitButton) {
                    $mouseButtonDownEventsSent = [int][Ws03NativeV2]::SendLeftButton($true)
                    Start-Sleep -Milliseconds 120
                    $mouseButtonUpEventsSent = [int][Ws03NativeV2]::SendLeftButton($false)
                }
                $mouseEventsSent = $mouseMoveEventsSent + $mouseButtonDownEventsSent + $mouseButtonUpEventsSent

                $clickDeadline = [DateTime]::UtcNow.AddSeconds(3)
                do {
                    Start-Sleep -Milliseconds 100
                    $uiReceipt = Get-ValuePatternText $receiptElement
                    $fileReceipt = if (Test-Path $receiptPath) { Get-Content -Raw -LiteralPath $receiptPath } else { '' }
                    $mouseEffectiveUiReceipt = $uiReceipt -eq $expectedReceipt
                    $mouseEffectiveFileReceipt = $fileReceipt -eq $expectedReceipt
                } while ((-not ($mouseEffectiveUiReceipt -and $mouseEffectiveFileReceipt)) -and [DateTime]::UtcNow -lt $clickDeadline)
            }
        }
    }
} catch {
    $probeErrorClass = $_.Exception.GetType().Name
    $probeErrorStage = 'caught: ' + [string]$_.Exception.Message
} finally {
    if ($null -ne $uiProcess) {
        try {
            if (-not $uiProcess.HasExited) {
                [void]$uiProcess.CloseMainWindow()
                if (-not $uiProcess.WaitForExit(1500)) {
                    $uiProcess.Kill($true)
                    $uiProcess.WaitForExit()
                }
            }
        } catch {
            try { $uiProcess.Kill($true) } catch { }
        }
    }
    Remove-Item -LiteralPath $uiScriptPath,$receiptPath -Force -ErrorAction SilentlyContinue
}

$sessionId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
$userInteractive = [Environment]::UserInteractive
$physicalDesktopAccepted = (
    $userInteractive -and
    $sessionId -gt 0 -and
    $inputDesktopOpened -and
    $uiaWindowFound -and
    $uiaInputFound -and
    $uiaButtonFound -and
    $uiaReceiptFound -and
    $screenshotCaptured -and
    $screenshotNonUniform -and
    $keyboardEventsSent -eq $keyboardEventsExpected -and
    $keyboardEffective -and
    $buttonClickablePointFound -and
    $physicalCursorReadback -and
    $cursorMoveEffective -and
    $cursorHitButton -and
    $mouseEventsSent -eq $mouseEventsExpected -and
    $mouseEffectiveUiReceipt -and
    $mouseEffectiveFileReceipt
)

$result = [ordered]@{
    schema_version = 2
    probe_revision = 'v2.1-mouse-diagnostic'
    provider_candidate = 'github_hosted_public_windows_2025'
    observed_at_utc = [DateTime]::UtcNow.ToString('o')
    github_actions = $env:GITHUB_ACTIONS -eq 'true'
    runner_os = $env:RUNNER_OS
    runner_arch = $env:RUNNER_ARCH
    image_os = $env:ImageOS
    image_version = $env:ImageVersion
    powershell_version = $PSVersionTable.PSVersion.ToString()
    user_interactive = $userInteractive
    session_id = $sessionId
    input_desktop_opened = $inputDesktopOpened
    uia_window_found = $uiaWindowFound
    uia_input_found = $uiaInputFound
    uia_button_found = $uiaButtonFound
    uia_receipt_found = $uiaReceiptFound
    screenshot_captured = $screenshotCaptured
    screenshot_non_uniform = $screenshotNonUniform
    screenshot_bytes = $screenshotBytes
    screenshot_width = $screenshotWidth
    screenshot_height = $screenshotHeight
    screenshot_sha256 = $screenshotSha256
    keyboard_sendinput_events_expected = $keyboardEventsExpected
    keyboard_sendinput_events_sent = $keyboardEventsSent
    keyboard_sendinput_effective = $keyboardEffective
    dpi_awareness_request_returned = $dpiAwarenessRequestReturned
    mouse_sendinput_events_expected = $mouseEventsExpected
    mouse_sendinput_events_sent = $mouseEventsSent
    mouse_move_events_sent = $mouseMoveEventsSent
    mouse_button_down_events_sent = $mouseButtonDownEventsSent
    mouse_button_up_events_sent = $mouseButtonUpEventsSent
    mouse_click_ui_receipt_effective = $mouseEffectiveUiReceipt
    mouse_click_file_receipt_effective = $mouseEffectiveFileReceipt
    button_enabled = $buttonEnabled
    button_offscreen = $buttonOffscreen
    button_center_x = $buttonCenterX
    button_center_y = $buttonCenterY
    button_clickable_point_found = $buttonClickablePointFound
    button_click_x = $buttonClickX
    button_click_y = $buttonClickY
    foreground_window_requested = $foregroundWindowRequested
    physical_cursor_readback = $physicalCursorReadback
    physical_cursor_x = $physicalCursorX
    physical_cursor_y = $physicalCursorY
    cursor_move_effective = $cursorMoveEffective
    cursor_hit_automation_id = $cursorHitAutomationId
    cursor_hit_button = $cursorHitButton
    physical_desktop_accepted = $physicalDesktopAccepted
    probe_error_class = $probeErrorClass
    probe_error_stage = $probeErrorStage
    uploads = 0
    secrets_consumed = 0
}

$json = $result | ConvertTo-Json -Compress -Depth 4
Write-Output "WS03_CANARY_JSON=$json"
if (-not $physicalDesktopAccepted) {
    Write-Output 'WS03_WINDOWS_GUI_STRONG=NOT_ACCEPTED'
    exit 3
}
Write-Output 'WS03_WINDOWS_GUI_STRONG=ACCEPTED'
