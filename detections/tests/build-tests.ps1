# detections/tests/build-tests.ps1 - glue each fixture to the REAL rule file, so tests never drift from the rules.
# Paste a generated tests/run/*.kql into a free Azure Data Explorer cluster (dataexplorer.azure.com/freecluster)
# or the Log Analytics query window. Each one returns Rows, Expected and Pass.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path; $rules = Split-Path -Parent $here
New-Item -ItemType Directory -Force "$here\run" | Out-Null
$expected = @{ '01' = 1; '02' = 1; '03' = 1; '04' = 3; '05' = 1; '06' = 1 }
foreach ($f in Get-ChildItem $rules -Filter '0*.kql') {
  $n = $f.Name.Substring(0, 2)
  $fixture = if ($n -eq '06') { 'fixture-signinlogs.kql' } else { 'fixture-securityevent.kql' }
  $body = (Get-Content "$here\$fixture" -Raw) + "`r`n" + (Get-Content $f.FullName -Raw).TrimEnd() +
          "`r`n| summarize Rows = count() | extend Expected = $($expected[$n]) | extend Pass = Rows == Expected`r`n"
  $body = $body -replace '\(count_ == 0 or true\) and ', ''
  [IO.File]::WriteAllText("$here\run\$n-test.kql", $body, (New-Object Text.UTF8Encoding $false))
}
"built: " + ((Get-ChildItem "$here\run").Name -join ', ')