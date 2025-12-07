$ErrorActionPreference = 'SilentlyContinue';
Get-ChildItem -Path C:\Windows\System32\Tasks\ -Recurse | ForEach-Object {
                        Select-String -Path $_.FullName -Pattern ":\\" 
                    } | Out-Gridview
