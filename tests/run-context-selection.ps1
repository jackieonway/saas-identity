param(
    [Parameter(Mandatory=$true)][string]$BaselineFile,
    [int]$Port=55437
)
$ErrorActionPreference='Stop'
if (-not [IO.Path]::IsPathFullyQualified($BaselineFile) -or -not (Test-Path -LiteralPath $BaselineFile)) { throw 'An explicit absolute baseline file is required' }
if ($Port -lt 1024 -or $Port -gt 65535) { throw 'Invalid test port' }
$testKeyFile=Join-Path ([IO.Path]::GetTempPath()) ('rust-saas-context-private-'+[guid]::NewGuid().ToString('N')+'.json')
try {
    node (Join-Path $PSScriptRoot 'generate-context-test-key.mjs') $testKeyFile
    if ($LASTEXITCODE -ne 0) { throw 'Disposable signing fixture generation failed' }
    $env:CONTEXT_SELECTION_TEST_ADMIN_URL="postgres://postgres@127.0.0.1:${Port}/postgres"
    $env:CONTEXT_SELECTION_BASELINE_FILE=$BaselineFile
    $env:CONTEXT_SELECTION_TEST_SIGNING_KEYS=$testKeyFile
    cargo test --locked --lib oidc::context -- --include-ignored --nocapture
    if ($LASTEXITCODE -ne 0) { throw 'Identity context selection tests failed' }
} finally {
    Remove-Item Env:CONTEXT_SELECTION_TEST_SIGNING_KEYS -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $testKeyFile) { Remove-Item -LiteralPath $testKeyFile -Force }
    Write-Output 'Disposable signing fixture removed'
}
