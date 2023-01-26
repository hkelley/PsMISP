
[datetime] $script:UnixEpoch = '1970-01-01 00:00:00Z'


Function Get-MISPAttributes
{
    param
    (
        [Parameter(Mandatory = $true)] [string] $ApiKey
        , [Parameter(Mandatory = $true)] [string] $UriBase 
        , [Parameter(Mandatory = $false)] [string] [ValidateSet('Network activity')] $MispAttributeCategory = 'Network activity'
        , [Parameter(Mandatory = $true)] [string]  [ValidateSet('domain','url','ip-dst','ip-src')] $MispAttributeType
        , [Parameter(Mandatory = $false)] [int]  $LookbackDays    
        , [Parameter(Mandatory = $false)] [string] $Tags 
        , [Parameter(Mandatory = $false)] [int] $MispPageSize = 100000
        , [Parameter(Mandatory = $false)] [bool] $enforceWarninglist = $true
        , [Parameter(Mandatory = $false)] [switch] $IncludeNonIDS
    )

    $url = "${UriBase}/attributes/restSearch"
    $headers = @{"Authorization"=$ApiKey;Accept='application/json';}

    $page = 1
    $attributeResults = @()
    $sw = New-Object System.Diagnostics.Stopwatch
    $sw.Start()
    $returnFormat = "json"

    Write-Verbose "Fetching page $page for type $t"
    do
    {
        $reqbody = [pscustomobject] @{
            page=$page++
            limit = $MispPageSize
            tags = $Tags
            includeEventTags = "true"
            type = $MispAttributeType
            category = $MispAttributeCategory
            enforceWarninglist = [int] $enforceWarninglist
            returnFormat = $returnFormat
        }

        if(-not $IncludeNonIDS)
        {
            $reqbody | Add-Member -NotePropertyName "to_ids"  -NotePropertyValue "true"
        }

        if($LookbackDays -gt 0)
        {            
            $reqbody | Add-Member -NotePropertyName "attribute_timestamp"  -NotePropertyValue ( "{0}d" -f $LookbackDays)
        }

        $body = ConvertTo-Json -InputObject $reqbody

        Write-Warning ("Requesting MISP attributes:  `r`n{0}" -f $body)

        # Using WebMethod so that we can access the headers
        $req = Invoke-WebRequest -UseBasicParsing -Uri $url -Headers $headers -ContentType "application/json" -Method Post -Body $body

        Write-Verbose ("Page {0} complete" -f  ($page - 1))

        switch($returnFormat)
        {
            "json" {
                $content = $req.Content | ConvertFrom-Json
                foreach($a in $content.response.Attribute)
                {
                    $attributeResults +=  [PSCustomObject] @{
                        indicator = $a.value
                        id  = $a.id 
                        event_id = $a.event_id
                        type = $a.type
                        timestamp = $a.timestamp
                        to_ids = $a.to_ids
                        confidence = $a.Tag | %{ if($ctag = ($_ | ?{$_.name -like "confidence:*" })) `
                                                     {($ctag.name -split ':')[1]}   }

                    }
                }
                
                Write-Verbose ("Fetched for type {1}: {2}   (page {0})" -f $page,$MispAttributeType,$content.response.Attribute.Count)
                break
            }
        }
    
    } while ($content.response.Attribute.Count)     #https://github.com/MISP/MISP/pull/4168   Keep pulling until you get an empty set [int] $req.Headers["X-Result-Count"]

    $sw.Stop()        
    Write-Verbose ("Result: {0}  {1} received in {2} seconds over {3} page(s)" -f $t,$req.Headers["X-Result-Count"],$sw.Elapsed.TotalSeconds,($page - 2))

    return $attributeResults
}


Export-ModuleMember -Function Get-MISPAttributes
