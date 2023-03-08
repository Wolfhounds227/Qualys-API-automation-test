#Combined BitSight API and Qualys SSL Server Checker API
#Author Ryan Server
#This script is used for verifying remediated findings from SSL configs through 
#Scanning the SSL server and returning whether or not it has key SSL vulnerabilities (Heartbleed ect),
#Checks certificate expiration, Checks whether weak protocols are in use (anything below TLS 1.2)
#Ideal scenario is to import an excel file with all your public IP/hostname combinations
#Script will run and scan against all rows in excel file which are the ip/hostname pairs and spit out an output text file with
# all data on findings and vulnerabilities or no vulns for an IP/hostname pair

$foundcollection = [System.Collections.ArrayList]@()
$notfoundcollection = [System.Collections.ArrayList]@()
$hasVulncollection = [System.Collections.ArrayList]@()
$noVulncollection = [System.Collections.ArrayList]@()
#Collection to store links for Analyzing a server hostname/ip combo
$AnalyzeCollection = [System.Collections.ArrayList]@()
$detailsCollection = [System.Collections.ArrayList]@()


$global:notFoundCounter = 0
$global:foundCounter =  0

$csv = Import-csv -delimiter "," -Path "C:\Users\$env:USERNAME\PATH_TO_INPUT_CSV_FILE"
$filepathoutput = "C:\Users\$env:USERNAME\Path_TO_OUTPUT_FILE.txt"
#output file and clearing contents each run.
Clear-content $filepathoutput


# excel  column variables to match column header name. This links the column header to the data in that row as it loops through all the rows 
# this script is built through a pipeline. output to input so as powershell works through the pipeline commands it identifies data
# via the column header variable names using pipeline variables
 


#TODO Main functions from SSLConfigCheckerCom script have been pulled into the function need to change the algos
# to work off multiple findings versus singular finding.
Function hostname_IPs_Scan {
    #SSL Checker API does not work with 'www.' at the front of a hostname. Need to do some quick regex and string manipulation
    # to check if 'www.' exists at the start of the string and splice it out before scanning.
    $matchedregexIP = ""
    $Global:hostofSite = $_.HostofSite
    $regex = [regex] "\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
    $APiAnalyzeStartString = "https://api.ssllabs.com/api/v3/analyze?host="
    $APiStartString = "https://api.ssllabs.com/api/v3/getEndpointData?host="

    $theHostN = $hostofSite
    if($theHostN.Substring(0,4) -eq "www."){

        $theHostN = $theHostN.Substring(4)
    }
    $analyzeend = '&publish=on'
    $InvokeAnalyze = $APiAnalyzeStartString+$theHostN+$analyzeend
    $checkAnalyze = Invoke-RestMethod $InvokeAnalyze -Verbose | ConvertTo-Json
    $checkAnalyzetest = Invoke-RestMethod $InvokeAnalyze -Verbose
    Start-Sleep -Seconds 1
    if($checkAnalyzetest.statusMessage -eq 'ERROR' -or $checkAnalyzetest.statusMessage -eq 'error' -or $checkAnalyzetest.status -eq "ERROR" -or $checkAnalyzetest.status -eq "error")
    {
        Write-Host "Unable to scan IP/hostname combination for "$theHostN -BackgroundColor Red
        $notFoundtoCollection = " " +$theHostN+" |"
        $notfoundcollection.Add($notFoundtoCollection)
        $global:notFoundCounter++


    }else {
    $matchedregexIP = $regex.Matches($checkAnalyze)[0].Value
    [string]$Ip = '&s='+$matchedregexIP
    $foundData = $theHostN + " " + $matchedregexIP 
    $notFoundData = $theHostN + " " + $matchedregexIP
    $VulnCounter = 0
    $InvokeData = $APiStartString+$theHostN+$Ip   
    $readyflag = 0
    $readyflagcounter = 0
    While($readyflag -eq 0){
    if($checkAnalyze.statusMessage -eq 'Ready' -or $checkAnalyze.status -eq "READY" -or $checkAnalyze.status -eq "Ready"){
        $readyflag = 1
    }
    Start-Sleep -Seconds 6
    $readyflagcounter++
    if($readyflagcounter -eq 3){
        $readyflag = 1
    }
    }
    $Data = Invoke-RestMethod $InvokeData -Verbose
    if($NULL -ne $data.ServerName) {
        $ServerName = $Data.ServerName
    }
    
    #test to make sure scan was successful if not Then store data into not found bucket to present later
    if($Data.errors.message -eq "Could not find assessment results for the host" -or $Data.errors.message -eq "Endpoint not found" -or $Data.errors.message -eq "Invalid host" -or $null-eq $Data){
        Write-Host "Unable to scan IP/hostname combination for "$notFoundData -BackgroundColor Red
        $notFoundtoCollection = $notFoundData+" | "
        $notfoundcollection.Add($notFoundtoCollection)
        $global:notFoundCounter++

        }else{
            $global:foundCounter++
            $foundtoCollection = $FoundData+" | "
            $foundcollection.Add($foundtoCollection)
           $protocols = $Data.details.protocols | ConvertTo-Json
           $ciphers = $Data.details.suites | ConvertTo-Json
            $foundtoDatacollection = " Number: " + $global:foundCounter + " | " + "ID: " + $foundData  + " | " + "Grade:"+ $Data.grade  + " | " + " Protocols:" + $protocols + " | " + " Ciphers:" + $ciphers + " | " +  "IPs: " + $regex.Matches($checkAnalyze) + " | " + "External Server Hostname: " + $ServerName + " || `n`n" 
            $detailsCollection.Add($foundtoDatacollection)
            Write-Host "Found: "$foundData" On Server:" $ServerName -BackgroundColor Green
        
    
    
    #$Data.details.protocols is where protocol versions is listed against scanned site.This will identify if TLS
    # 1.0 or 1.1 or 1.2 is being used.
    
    # TLS 1.0 key id is 769
    if($Data.details.protocols.version -eq '1.0'){
    write-host $theHostN 'uses TLS 1.0. TLS 1.0 not part of GIS standards and is considered a weak protocol.' -BackgroundColor Red
    $VulnCounter++
    }
    #TLS 1.1 key id is 770
    if($Data.details.protocols.version -eq '1.1'){
    write-host $theHostN 'uses TLS 1.1. TLS 1.1 not part of GIS standards and is considered a weak protocol.' -BackgroundColor Red
    $VulnCounter++
    }
    # Logic is if details are flagged false it is nwrite-host $theHostN 'uses TLS 1.1. TLS 1.1 not part of GIS standards and is considered a weak protocol.' -BackgroundColor Redot vulnerable or if the engine did not run the vulnerable test and the variable
    # is not present aka NULL we assume it is not vulnerable. If the test is flagged with the boolean TRUE then the SSL engine assumes
    # based off testing it is vulnerable to the drown vulnerability.
    if($null -ne $Data){
    if($Data.details.drownVulnerable -eq $false){
    write-host $theHostN 'Is not vulnerable to the drown vulnerability' -BackgroundColor Green
    }elseif($null -eq $Data.details.drownVulnerable){

    }else{
    write-host $theHostN 'Is vulnerable to the drown vulnerability' -BackgroundColor Red
    $VulnCounter++
    }
    if($Data.details.freak -eq $false){
    write-host $theHostN 'Is not vulnerable to the freak vulnerability' -BackgroundColor Green
    }elseif($null -eq $Data.details.freak){

    }else{
    write-host $theHostN 'Is vulnerable to the freak vulnerability' -BackgroundColor Red
    $VulnCounter++
    }
    
}
    if($VulnCounter -ne 0){
        $foundData+=$hasVulncollection

    }else{
        $notFoundData+=$noVulncollection
    }

        
        }

}
}


#Main Loop. Run the function against each row in excel spreadsheet.

$csv | ForEach-object{hostname_IPs_Scan}

"Assets found = " + $global:foundCounter + " | Assets Not found =" + $global:notFoundCounter | out-file -Append $filepathoutput 


"Found assets with vulnerabilities: "+ $foundcollection | out-file -Append $filepathoutput

"Not Found assets:" + $notfoundcollection | out-file -Append $filepathoutput

"Details for found assets:" + $detailsCollection | out-file -Append $filepathoutput

#Uncomment below this last part for final output when testing is complete
Invoke-Item -Path $filepathoutput 