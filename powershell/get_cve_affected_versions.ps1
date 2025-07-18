$base_url = "https://cveawg.mitre.org/api/cve/"

param(
    [string]$inputpath = "",
    [string]$outputpath = "",
    [string]$cvecolumnname = "",
    [string]$newcolumnname = ""
)

if ([string]::IsNullOrWhiteSpace($inputpath) -or
    [string]::IsNullOrWhiteSpace($outputpath) -or
    [string]::IsNullOrWhiteSpace($cvecolumnname) -or
    [string]::IsNullOrWhiteSpace($newcolumnname)) {
    Write-Error "One or more required parameters are missing or empty."
    exit 1
}

$csv_data = Import-Csv -Path $inputpath

foreach ($row in $csv_data) {
    $cve = $row.$cvecolumnname

    try {
        $url = $base_url+$cve
        $mitre_response = Invoke-RestMethod -Uri $url -Method Get
        $mitre_version = $mitre_response.containers.cna.affected.versions.version
        if($mitre_version -is [array]) {
            foreach($version_line in $mitre_version) {
                if ($version_line -ne "unspecified" -and $version_line -ne "0" -and $version_line -ne "n/a") {
                    $output = $output + $version_line
                }
                else {
                    $output = ""
                }
            }
            $mitre_version = $output
        }
        elseif($mitre_version -eq "0") {
            $mitre_version = $mitre_response.containers.cna.affected.versions.lessThanOrEqual
        }
        elseif($mitre_version -eq "n/a") {
            $mitre_version = "n/a"
        }
        else {
            Write-Output("Edge case response found for " + $cve + ": " + $mitre_version)
            $mitre_version = ""
        }
        $row | Add-Member -NotePropertyName $newcolumnname -NotePropertyValue $mitre_version -Force
    } catch {
        Write-Warning "API call failed for '$value': $_"
    }
}

$csv_data | Export-Csv -Path $outputpath -NoTypeInformation
Write-Output("Processing Complete")