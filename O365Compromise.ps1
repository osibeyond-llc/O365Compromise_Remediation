


#Office 365 Email Compromise remediation automation
#Script written by Benjamin Cornwell of OSIbeyond

Write-Host "Welcome to the Office 365 Account Compromise Remediation Tool" -ForegroundColor Yellow
$user = ""
while($user -eq ""){
    $user =Read-Host "To Begin, enter the full email address of the compromised user"
}
Write-Host "Compromised user account: " -ForegroundColor Yellow -NoNewline
Write-Host "$user" -ForegroundColor DarkMagenta


#connect to MSOnline (for account management).
Connect-MSOLService  #authenticate

#disable user account (sets sign-in status to BLOCKED)
$confirm = ""
Write-Host "Do you want to block the user from sign in? (default is 'yes')" -ForegroundColor DarkMagenta
$confirm = Read-Host " >>"
$cofirm.ToLower
if (($confirm -eq "no") -or ($confirm -eq "n")){
    Write-Host "User was not blocked from sign-in. " -ForegroundColor Yellow -NoNewLine
    Write-Host "This is not advised." -ForegroundColor Red
}else{
    Set-MsolUser -UserPrincipalName $user -BlockCredential $true
    Write-Host "User has been " -ForegroundColor Cyan -NoNewLine
    Write-Host "blocked" -ForegroundColor Yellow -NoNewLine 
    Write-Host " from sign in to Office 365." -ForegroundColor Cyan -NoNewLine
}
#Environmental variable to import module - must be pre-installed from O365 EAC > Hybrid > Setup > Install
$CreateEXOPSSession = (Get-ChildItem -Path $env:userprofile -Filter CreateExoPSSession.ps1 -Recurse -ErrorAction SilentlyContinue -Force | Select -Last 1).DirectoryName
. "$CreateEXOPSSession\CreateExoPSSession.ps1"

#connect to office365 - works with MFA
Connect-EXOPSsession #authenticate

Write-Host "Connected ..." -ForegroundColor Green
Write-Host "Testing Connectivity with" -ForegroundColor Cyan -NoNewLine
Write-Host " Get-MailBox (10)" -ForegroundColor Yellow -NoNewline
Write-Host " ... " -ForegroundColor Cyan
try{ Get-Mailbox -ResultSize 10 }
catch [System.Management.Automation.CommandNotFoundException]
{
    "Get-MailBox command failed - you are not connected to a valid O365 admin account. Please try again." 
    Connect-EXOPSSession
}
## TRY CATCH WTH OPTION TO CHANGE $user
try{
    Write-Host "Fetching Mailbox ..." -ForegroundCOlor Yellow
    $Global:ErrorActionPreference = ‘Stop’
    Get-Mailbox $user | fl -ErrorAction 'Stop'
}
catch{
    Write-Host "Unable to find mailbox. Is `" $user `" the correct address?" -ForegroundColor Red
    Write-Host "Please enter email address again." -ForegroundColor Yellow
    $user = Read-Host ">>"
    Get-Mailbox $user | fl
    Write-Host "Mailbox retrieval succeeded. Proceeding ..." -ForegroundColor Green
}



#list forwarding rules 
Write-Host "Checking rules for external forwarding in mailbox: $user ..." -ForegroundColor Cyan
$domains = Get-AcceptedDomain
$rules = Get-InboxRule -mailbox $user
if ($rules -eq $NULL){ Write-Host "No rules found - $user has no inbox rules enabled." -ForegroundCOlor Green }
else{
    $forwardingRules = $null
    $rules = Get-InboxRule -Mailbox $user
    
    $forwardingRules = $rules | Where-Object {$_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo}
    foreach ($rule in $forwardingRules) {
        $count = 0
        Write-Host "Rule : $rule" -ForegroundColor DarkRed
        Get-InboxRule -Identity $rule.Identity | fl Name,ForwardTo,ForwardAsAttachmentTo,RedirectTo
        $confirmation = Read-Host "Do you want to remove this rule? (Y/n)"
        if ($confirmation.ToLower -eq 'y'){
            Get-InboxRule -Identity $rule.Identity | Remove-InboxRule
            $count ++
        }
    }
    Write-Host "You removed " -ForegroundColor Cyan -NoNewLine -BackgroundColor DarkGray
    Write-Host "$count" -ForegroundColor Yellow -NoNewLine -BackgroundColor DarkGray
    Write-Host " forwarding rules" -ForegroundColor Cyan -BackgroundColor DarkGray
}

#Change users password (account can be disabled or enabled)
$password = ""
$confirmation = ""
while($confirmation -eq ""){
    $confirmation = Read-Host "Do you want to change the user's password? (Y/n)"
    $confirmation.ToLower
    if(($confirmation -eq "y") -or ($confirmation -eq "yes")){
        $failed = "True"
        while($password -eq ""){
            Write-Host "Please enter a new password for the user"  -ForegroundColor Cyan
            Write-Host "Password must comply with the following requirements:"  -ForegroundColor Cyan
            Write-Host "  -  At least 8 characters" -ForegroundColor Yellow
            Write-Host "  -  Uppercase" -ForegroundColor Yellow
            Write-Host "  -  Lowercase" -ForegroundColor Yellow
            Write-Host "  -  Numbers" -ForegroundColor Yellow
            Write-Host "  -  Special Chars" -ForegroundColor Yellow
            $password = Read-Host "Enter new password here"
        Write-Host "New temporary password is: $password    -  This will be saved for your review later."

        #needs to be validated with below method:
        Write-Host "Changing password now..." -ForegroundColor Yellow
        Set-MsolUserPassword -UserPrincipalName $user -NewPassword $password
        Write-Host "Password Changed sucessfully." -ForegroundColor Green
        }
    }
    else 
    {
        Write-Host "Password will not be changed." -ForegroundColor Yellow
    }

}
    #Check OAuth 
    Write-Host "Do you want to check OAuth access? (External .PS1 must be supplied and available in C:\Temp) (Y/n)" -ForegroundColor Cyan
    $confirmation = Read-Host " >>"
    $confirmation.ToLower
    if(($confirmation -eq "y") -or ($confirmation -eq "yes")){
        Write-Host "Checking OAuth Hijacking ..." -ForegroundCOlor Cyan
        Connect-AzureAD
        C:\Users\bcornwell\Documents\Get-AzureADPSPermissions.ps1 -ShowProgress -UserProperties @("DisplayName", "UserPrincipalName", "Mail") -ServicePrincipalProperties @("DisplayName", "AppId") | Where-Object {$_.UserPrincipalName -like $user}
    }
    else{
        Write-Host "Not Checking Oauth ..." -ForegroundColor Red
    }
    Write-Host ""
  #hold new password until the end

    #output written confirmation if tech chekced mimecast
    $confirmation = Read-Host "Please check Mimecast mail logs to identify any other outbound spam, and confirm Y/n when done. (Y/n)"
    if ($confirmation.ToLower -eq 'y'){
        break
        }
    #use O365 message tracking to identify spam and return recipient and subject of all messages in last 24 hours
    $dateEnd = Get-Date
    Write-Host "Current datetime = $dateEnd"
    $dateStart = $dateEnd.AddHours(-24)
    $trace = Get-MessageTrace -startdate $dateStart -EndDate $dateEnd -SenderAddress $user | Select-Object Date,SenderAddress,RecipientAddress,Subject,Status,MessageID
    $trace | Out-GridView
    $spam_subject = ""
    ## Add option to Skip this if no spam was reported.
    $spam_subject = Read-Host "Subject line of spam letter >>"
    $spamRecipients = @()

    foreach ($message in $trace){
        $trace | where {$_.Subject -like $spam_subject} | ft -Wrap
        #This doesnt work
        $spamRecipients += $_.RecipientAddress
    }

    

    Write-Host "Please identify the messages that are suspicious, and send a screenshot of the GridView to the PoC. Include the following template (also `
    available from internal_template.txt on the desktop. The PoC should send it to anyone who recieved spam from the compromised account." -ForegroundColor DarkRed -BackgroundColor White
    
    
    
    $body = "Hello [User], `
    We were recently alerted to a spam message addressed to you, originating from one of our accounts. This has be remediated on our end, and if you have `
    received such a message from $user, We ask that you delete it without clicking on any of the links. If you ever see any of these in the future, either `
    from external senders or people within your company, please forward it to support@osibeyond.com. `
    Thanks, `
    OSIbeyond,"

    Write-Host "Please see below for a list of users who have received a message with a subject line matching the spam pattern declared earlier:" -ForegroundColor Cyan
    Write-Host "$spamRecipients"
    Write-Host ""
    Write-Host "Please see the following template for a message to internal and external recipients - The operator should send this to every in the above array." -ForegroundColor Cyan
    Write-Host "$body" -ForegroundColor Yellow
    Write-Host ""

    #we need a dedicated centralized mail account without MFA from which we can send the messages, needs to be whitelisted in all Mimecast 


    #ask for confirmation before re-enabling account and returning password to tech - must be told over phone call
    $confirmation = Read-Host "Has the POC been contacted, and is this account ready to be re-enabled? (Y/n)"
    $confirmation.ToLower
    if(($confirmation -eq "y") -or ($confirmation -eq "yes")){
        Set-MsolUser -UserPrincipalName $user -BlockCredential $false
        #WILL BE FORCED TO MAKE A NEW PASSWORD
        if ($password -eq ""){
            Write-Host "Operation complete. Goodbye." -ForegroundColor Green
            Start-Sleep -Seconds 3
            exit
        }else{
            Write-Host "New Password:  $password" -ForegroundColor Green
            Start-Sleep -Seconds 3
            Write-Host "Operation complete. Goodbye." -ForegroundColor Green
            Start-Sleep -Seconds 3
            exit
    }
    else{
        Write-Host "Please re-enable the account on your own time and then contact the PoC. Thank you. Goodbye." -ForegroundColor Green
        Start-Sleep -Seconds 3
        exit
    }
    
