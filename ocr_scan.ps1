# SentinelGate — Windows Native OCR Scanner
# Uses the Windows.Media.Ocr WinRT API (built into Windows 10+, zero install)
# Usage: powershell -ExecutionPolicy Bypass -File ocr_scan.ps1 -ImagePath "C:\path\to\image.png"

param(
    [Parameter(Mandatory=$true)]
    [string]$ImagePath
)

try {
    Add-Type -AssemblyName System.Runtime.WindowsRuntime

    # Helper: Await WinRT async operations from PowerShell
    $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { 
        $_.Name -eq 'AsTask' -and 
        $_.GetParameters().Count -eq 1 -and 
        $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' 
    })[0]

    function Await($WinRtTask, $ResultType) {
        $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
        $netTask = $asTask.Invoke($null, @($WinRtTask))
        $netTask.Wait(-1) | Out-Null
        $netTask.Result
    }

    # Load WinRT types
    [void][Windows.Graphics.Imaging.BitmapDecoder,Windows.Foundation,ContentType=WindowsRuntime]
    [void][Windows.Media.Ocr.OcrEngine,Windows.Foundation,ContentType=WindowsRuntime]

    # Open file as stream
    $fileStream = [System.IO.File]::OpenRead($ImagePath)
    $randomAccessStream = [System.IO.WindowsRuntimeStreamExtensions]::AsRandomAccessStream($fileStream)

    # Decode the image
    $decoder = Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($randomAccessStream)) ([Windows.Graphics.Imaging.BitmapDecoder])
    $bitmap = Await ($decoder.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])

    # Create OCR engine from user's language profile
    $ocrEngine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()

    if ($null -eq $ocrEngine) {
        Write-Error "OCR Engine could not be created. Ensure language packs are installed."
        exit 1
    }

    # Run OCR
    $ocrResult = Await ($ocrEngine.RecognizeAsync($bitmap)) ([Windows.Media.Ocr.OcrResult])

    # Cleanup
    $fileStream.Close()
    $fileStream.Dispose()

    # Output result
    Write-Output $ocrResult.Text

} catch {
    Write-Error "OCR Failed: $_"
    exit 1
}
