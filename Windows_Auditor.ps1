#Program Name :- Windows Auditor Based on CIS Benchmark 
#Program Name :- Windows Auditor Based on CIS Benchmark 
#Benchmark File used :- CIS_Microsoft_Windows_Server_2012_Benchmark_v1.0.0
#Author : Kaustubh Padwad
#copyright : copyright (c) 2015 Kaustubh Padwad
#Licnse :- Gnu-GPL-3
Set-ExecutionPolicy -ExecutionPolicy restricted -force
echo "1 Checks for Computer Configuration"
echo "1.1 Security Settings"
echo "1.1.1 Account Policies" > audit.txt

echo "1.1.1.1 Set 'Account lockout threshold' to '5 invalid logon attempt(s)'" 
echo "Account lockout threshold Should be 5 OR LESS invalid logon attempt(s)'" >> audit.txt
$a = "Account lockout threshold-----------> "
$b = net accounts | findstr /i /c:"lockout threshold"
$a += if ($b -match "5") {echo "compliance"} else {echo "Non compliance this value should be less than 5"}
write-output $a

echo "1.1.1.2 Set 'Account lockout duration' to '15 or more minute(s)'" 
echo "Account lockout duration' to '15 or more minute(s)''" >> audit.txt
$a = "Account lockout duration-----------> "
$b = net accounts | findstr /i /c:"lockout duration"
$a += if ($b -match "15") {echo "compliance"} else {echo "Non compliance this value should be 15"}
write-output $a

echo "1.1.1.3 Set 'Reset account lockout counter after' to '15 minute(s)'" 
echo "Reset account lockout counter after' to '15 minute(s)" >> audit.txt
$a = "Reset account lockout counter-----------> "
$b = net accounts | findstr /i /c:"lockout duration"
$a += if ($b -match "30") {echo "compliance"} else {echo "Non compliance this value should be 30"}
write-output $a

echo "1.1.1.4 Set 'Minimum password length' to '14 or more character(s)" 
echo "Minimum password length to '14 or more character(s)" >> audit.txt
$a = "Minimum password length-----------> "
$b = net accounts | findstr /i /c:"Minimum password length"
$a += if ($b -match "14") {echo "compliance"} else {echo "Non compliance this value should be 14"}
write-output $a

echo "1.1.1.5 Set 'Enforce password history' to '24 or more password(s)'" 
echo "Enforce password history' to '24" >> audit.txt
$a = "Enforce password history-----------> "
$b = net accounts | findstr /i /C:"password history"
$a += if ($b -match "24") {echo "compliance"} else {echo "Non compliance this value should be 24"}
write-output $a

echo "1.1.1.6 Set 'Password must meet complexity requirements' to 'Enabled'" 
echo "Password must meet complexity requirements' to 'Enabled'" >> audit.txt
$a = " Password must meet complexity-----------> "
$b = net accounts | findstr /i /C:"password history"
$a += if ($b -match "24") {echo "compliance"} else {echo "Non compliance this value should be 24"}
write-output $a

#echo "1.1.1.7 Set 'Store passwords using reversible encryption' to 'Disabled'" 
#echo "'Store passwords using reversible encryption' to 'Disabled'" >> audit.txt
#$a = " Store passwords using reversible encryption-----------> "
#$b = "
#$a += if ($b -match "24") {echo "compliance"} else {echo "Non compliance this value should be 24"}
#write-output $a

echo "1.1.1.8 Set 'Minimum password age' to '1 or more day(s)'" 
echo "Minimum password age' to '1'" >> audit.txt
$a = " Minimum password age-----------> "
$b = net accounts | findstr /i /c:"Minimum password age"
$a += if ($b -match "1") {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "1.1.1.9 Set 'Maximum password age' to '60 or fewer days'" 
echo "Maximum password age' to '60'" >> audit.txt
$a = " Maximum password age-----------> "
$b = net accounts | findstr /i /c:"Maximum password age"
$a += if ($b -match "60") {echo "compliance"} else {echo "Non compliance this value should be 60"}
write-output $a

echo "1.1.2 Advanced Audit Policy Configuration"

echo "1.1.2.1 Set 'Audit Policy: Account Logon: Credential Validation' to 'Success and Failure'" 
echo "Audit Policy: Account Logon: Credential Validation' to 'Success and Failure'" >> audit.txt
$a = " Audit Policy: Account Logon: Credential Validation -----------> "
$b = auditpol /get /category:* | findstr /i "cread"
$a += if ($b -match "Success and Failure") {echo "compliance"} else {echo "Non compliance this value should be Success and Failure"}
write-output $a

echo "1.1.2.2 Set 'Audit Policy: Account Logon: Kerberos Authentication Service' to 'No Auditing'" 
echo "Account Logon: Kerberos Authentication Service' to 'No Auditing'" >> audit.txt
$a = " Account Logon: Kerberos Authentication Service -----------> "
$b = auditpol /get /category:* | findstr /i /c:"Kerberos Authentication Service"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a

echo "1.1.2.3 Set 'Audit Policy: Account Logon: Kerberos Service Ticket Operations' to 'No Auditing'" 
echo "Account Logon: Kerberos Authentication Service' to 'No Auditing'" >> audit.txt
$a = " Account Logon: Kerberos Authentication Service -----------> "
$b = auditpol /get /category:* | findstr /i /c:"Kerberos Service"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a

echo "1.1.2.4 Set 'Audit Policy: Account Logon: Other Account Logon Events' to 'No Auditing'" 
echo "'Audit Policy: Account Logon: Other Account Logon Events' to 'No Auditing'" >> audit.txt
$a = " Account Logon: Other Account Logon Events -----------> "
$b = auditpol /get /category:* | findstr /i /c:"Other Account Logon"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a

echo "1.1.2.5 Set 'Audit Policy: Account Management: Application Group Management' to 'No Auditing'" 
echo "Audit Policy: Account Management: Application Group Management"' to 'No Auditing" >> audit.txt
$a = " Account Management: Application Group Management -----------> "
$b = auditpol /get /category:* | findstr /i /c:"Application Group Management"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.7 Set 'Audit Policy: Account Management: Distribution Group Management' to 'No Auditing'" 
echo "Audit Policy: Account Management: Distribution Group Management" >> audit.txt
$a = " Account Management: Distribution Group Management-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Computer Account Management"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.8 Set 'Audit Policy: Account Management: Other Account Management Events' to 'Success and Failure'" 
echo "Audit Policy: Account Management: Other Account Management Events" >> audit.txt
$a = " Account Management: Other Account Management Events-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Computer Account Management"
$a += if ($b -match "Success and Failure") {echo "compliance"} else {echo "Non compliance this value should be Success and Failure"}
write-output $a
echo "1.1.2.9 Set 'Audit Policy: Account Management: Security Group Management' to 'Success and Failure'" 
echo "Audit Policy: Account Management: Security Group Management" >> audit.txt
$a = " Account Management: Security Group Management-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Security Group Management"
$a += if ($b -match "Success and Failure") {echo "compliance"} else {echo "Non compliance this value should be Success and Failure"}
write-output $a
echo "1.1.2.10 Set 'Audit Policy: Account Management: User Account Management' to 'Success and Failure'" 
echo "Audit Policy: Account Management: User Account Management" >> audit.txt
$a = " Account Management: User Account Management-----------> "
$b = auditpol /get /category:* | findstr /i /c:"User Account Management"
$a += if ($b -match "Success and Failure") {echo "compliance"} else {echo "Non compliance this value should be Success and Failure"}
write-output $a
echo "1.1.2.11 Set 'Audit Policy: Detailed Tracking: DPAPI Activity' to 'No Auditing'" 
echo "Audit Policy: Detailed Tracking: DPAPI Activity" >> audit.txt
$a = " Detailed Tracking: DPAPI Activity-----------> "
$b = auditpol /get /category:* | findstr /i /c:"DPAPI Activity"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.12 Set 'Audit Policy: Detailed Tracking: Process Creation' to 'Success'" 
echo "Audit Policy: Detailed Tracking: Process Creation" >> audit.txt
$a = " Detailed Tracking: Process Creation-----------> "
$b = auditpol /get /category:* | findstr /i /c:"DPAPI Activity"
$a += if ($b -match "Success") {echo "compliance"} else {echo "Non compliance this value should be Success"}
write-output $a
echo "1.1.2.13 Set 'Audit Policy: Detailed Tracking: Process Termination' to 'No Auditing'" 
echo "Audit Policy: Detailed Tracking: Process Termination" >> audit.txt
$a = " Detailed Tracking: Process Termination-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Process Termination"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.14 Set 'Audit Policy: Detailed Tracking: RPC Events' to 'No Auditing'" 
echo "Audit Policy: Detailed Tracking: RPC Events" >> audit.txt
$a = " Detailed Tracking: RPC Events-----------> "
$b = auditpol /get /category:* | findstr /i /c:"RPC Events"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.15 Set 'Audit Policy: DS Access: Detailed Directory Service Replication' to 'No Auditing'" 
echo "Audit Policy: DS Access: Detailed Directory Service Replication" >> audit.txt
$a = " DS Access: Detailed Directory Service Replication-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Detailed Directory Service Replication"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.16 Set 'Audit Policy: DS Access: Directory Service Access' to 'Success and Failure'" 
echo "Audit Policy: DS Access: Directory Service Access" >> audit.txt
$a = " DS Access: Directory Service Access-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Directory Service Access"
$a += if ($b -match "Success and Failure") {echo "compliance"} else {echo "Non compliance this value should be Success and Failure"}
write-output $a
echo "1.1.2.16 Set 'Audit Policy: DS Access: Directory Service Access' to 'Success and Failure'" 
echo "Audit Policy: DS Access: Directory Service Access" >> audit.txt
$a = " DS Access: Directory Service Access-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Directory Service Access"
$a += if ($b -match "Success and Failure") {echo "compliance"} else {echo "Non compliance this value should be Success and Failure"}
write-output $a
echo "1.1.2.17 Set 'Audit Policy: DS Access: Directory Service Changes' to 'Success and Failure'" 
echo "Audit Policy: DS Access: Directory Service Changes" >> audit.txt
$a = " DS Access: Directory Service Changes-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Directory Service Changes"
$a += if ($b -match "Success and Failure") {echo "compliance"} else {echo "Non compliance this value should be Success and Failure"}
write-output $a
echo "1.1.2.18 Set 'Audit Policy: DS Access: Directory Service Replication' to 'No Auditing'" 
echo "Audit Policy: DS Access: Directory Service Replication" >> audit.txt
$a = " DS Access: Directory Service Replication-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Directory Service Replication"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.19 Set 'Audit Policy: Logon-Logoff: Account Lockout' to 'No Auditing'" 
echo "Audit Policy: Logon-Logoff: Account Lockout' to 'No Auditing" >> audit.txt
$a = " Logon-Logoff: Account Lockout-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Account Lockout"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.20 Set 'Audit Policy: Logon-Logoff: IPsec Extended Mode' to 'No Auditing'" 
echo "Audit Policy: Logon-Logoff: IPsec Extended Mode' to 'No Auditing" >> audit.txt
$a = " Logon-Logoff: Account Lockout-----------> "
$b = auditpol /get /category:* | findstr /i /c:"IPsec Extended Mode"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.22 Set 'Audit Policy: Logon-Logoff: IPsec Quick Mode' to 'No Auditing'" 
echo "Audit Policy: Logon-Logoff: IPsec Quick Mode' to 'No Auditing" >> audit.txt
$a = " Logon-Logoff: IPsec Quick Mode-----------> "
$b = auditpol /get /category:* | findstr /i /c:"IPsec Quick Mode"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.23 Set 'Audit Policy: Logon-Logoff: Logoff' to 'Success'" 
echo "Audit Policy: Logon-Logoff: Logoff' to 'Success" >> audit.txt
$a = " Logon-Logoff: Logoff>----------->> "
$b = auditpol /get /category:* | findstr /i /c:"Logoff"
$a += if ($b -match "Success") {echo "compliance"} else {echo "Non compliance this value should be Success"}
write-output $a
echo "1.1.2.24 Set 'Audit Policy: Logon-Logoff: Logon' to 'Success and Failure'" 
echo "Audit Policy: Logon-Logoff: Logon' to 'Success" >> audit.txt
$a = " Logon-Logoff: Logon>----------->> "
$b = auditpol /get /category:* | findstr /i /c:"Logon"
$a += if ($b -match "Success and Failure") {echo "compliance"} else {echo "Non compliance this value should be Success and Failure"}
write-output $a
echo "1.1.2.25 Set 'Audit Policy: Logon-Logoff: Network Policy Server' to 'No Auditing'" 
echo "Audit Policy: Logon-Logoff: Network Policy Server' to 'No Auditing" >> audit.txt
$a = " Logon-Logoff: Network Policy Server-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Network Policy Server"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.26 Set 'Audit Policy: Logon-Logoff: Other Logon/Logoff Events' to 'No Auditing'" 
echo "Audit Policy: Logon-Logoff: Other Logon/Logoff Events' to 'No Auditing" >> audit.txt
$a = " Logon-Logoff: Other Logon/Logoff Events-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Other Logon/Logoff Events"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.27 Set 'Audit Policy: Logon-Logoff: Special Logon' to 'Success'" 
echo "Audit Policy: Logon-Logoff: Special Logon' to 'Success" >> audit.txt
$a = " Logon-Logoff: Special Logon-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Special Logon"
$a += if ($b -match "Success") {echo "compliance"} else {echo "Non compliance this value should be Success"}
write-output $a
echo "1.1.2.27 Set 'Audit Policy: Logon-Logoff: Special Logon' to 'Success'" 
echo "Audit Policy: Logon-Logoff: Special Logon' to 'Success" >> audit.txt
$a = " Logon-Logoff: Special Logon-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Special Logon"
$a += if ($b -match "Success") {echo "compliance"} else {echo "Non compliance this value should be Success"}
write-output $a
echo "1.1.2.28 Set 'Audit Policy: Object Access: Application Generated' to 'No Auditing'" 
echo "Audit Policy: Object Access: Application Generated'' to 'No Auditing" >> audit.txt
$a = " Object Access: Application Generated'-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Application Generated"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.29 Set 'Audit Policy: Object Access: Central Access Policy Staging' to 'No Auditing'" 
echo "Audit Policy: Object Access: Central Access Policy Staging' to 'No Auditing" >> audit.txt
$a = " Object Access: Central Access Policy Staging'-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Central Access Policy Staging"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.30 Set 'Audit Policy: Object Access: Certification Services' to 'No Auditing'" 
echo "Audit Policy: Object Access: Certification Services' to 'No Auditing" >> audit.txt
$a = " Object Access: Central Certification Services-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Certification Services"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.31 Set 'Audit Policy: Object Access: Detailed File Share' to 'No Auditing'" 
echo "Audit Policy: Object Access: Detailed File Share' to 'No Auditing" >> audit.txt
$a = " Object Access: Detailed File Share-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Detailed File Share"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.32 Set 'Audit Policy: Object Access: File Share' to 'No Auditing'" 
echo "Audit Policy: Object Access: File Share' to 'No Auditing" >> audit.txt
$a = " Object Access: File Share-----------> "
$b = auditpol /get /category:* | findstr /i /c:"  File Share"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.33 Set 'Audit Policy: Object Access: File System' to 'No Auditing'" 
echo "Audit Policy: Object Access: File System to 'No Auditing" >> audit.txt
$a = " Object Access: File System-----------> "
$b = auditpol /get /category:* | findstr /i /c:"File System"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.34 Set 'Audit Policy: Object Access: Filtering Platform Connection' to 'No Auditing'" 
echo "Audit Policy: Object Access: Filtering Platform Connection to 'No Auditing" >> audit.txt
$a = " Object Access: Filtering Platform Connection-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Filtering Platform Connection"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.35 Set 'Audit Policy: Object Access: Filtering Platform Packet Drop' to 'No Auditing'" 
echo "Audit Policy: Object Access: Filtering Platform Packet Drop to 'No Auditing" >> audit.txt
$a = " Object Access: Filtering Platform Packet Drop-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Filtering Platform Packet Drop"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.36 Set 'Audit Policy: Object Access: Handle Manipulation' to 'No Auditing'" 
echo "Audit Policy: Object Access: Handle Manipulation to 'No Auditing" >> audit.txt
$a = " Object Access: Handle Manipulation-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Handle Manipulation"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.37 Set 'Audit Policy: Object Access: Kernel Object' to 'No Auditing'" 
echo "Audit Policy: Object Access: Kernel Object to 'No Auditing" >> audit.txt
$a = " Object Access: Kernel Object-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Kernel Object"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.38 Set 'Audit Policy: Object Access: Other Object Access Events' to 'No Auditing'" 
echo "Audit Policy: Object Access: Other Object Access Events to 'No Auditing" >> audit.txt
$a = " Object Access: Other Object Access Events-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Other Object Access Events"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.39 Set 'Audit Policy: Object Access: Registry' to 'No Auditing'" 
echo "Audit Policy: Object Access: Registry to 'No Auditing" >> audit.txt
$a = " Object Access: Registry-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Registry"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.40 Set 'Audit Policy: Object Access: Removable Storage' to 'No Auditing'" 
echo "Audit Policy: Object Access: Removable Storage to 'No Auditing" >> audit.txt
$a = " Object Access: Removable Storage-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Removable Storage"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.41 Set 'Audit Policy: Object Access: SAM to 'No Auditing'" 
echo "Audit Policy: Object Access: SAM to 'No Auditing" >> audit.txt
$a = " Object Access: SAM-----------> "
$b = auditpol /get /category:* | findstr /i /c:"SAM"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.42 Set 'Audit Policy: Policy Change: Audit Policy Change' to 'Success and Failure'" 
echo "Audit Policy: Policy Change: Audit Policy Change to 'No Auditing" >> audit.txt
$a = " Policy Change: Audit Policy Change-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Audit Policy Change"
$a += if ($b -match "Success and Failure") {echo "compliance"} else {echo "Non compliance this value should be Success and Failure"}
write-output $a
echo "1.1.2.43 Set 'Audit Policy: Policy Change: Authentication Policy Change' to 'Success'" 
echo "Audit Policy: Policy Change: Authentication Policy Change to 'No Auditing'" >> audit.txt
$a = " Policy Change: Audit Policy Change-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Authentication Policy Change"
$a += if ($b -match "Success") {echo "compliance"} else {echo "Non compliance this value should be Success"}
write-output $a
echo "1.1.2.44 Set 'Audit Policy: Policy Change: Authorization Policy Change' to 'No Auditing'" 
echo "Audit Policy: Policy Change: Authorization Policy Change to 'No Auditing'" >> audit.txt
$a = " Policy Change: Authorization Policy Change-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Authorization Policy Change"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.45 Set 'Audit Policy: Policy Change: Filtering Platform Policy Change' to 'No Auditing'" 
echo "Audit Policy: Policy Change: Filtering Platform Policy Change to 'No Auditing'" >> audit.txt
$a = " Policy Change: Filtering Platform Policy Change-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Filtering Platform Policy Change"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.46 Set 'Audit Policy: Policy Change: MPSSVC Rule-Level Policy Change' to 'No Auditing'" 
echo "Audit Policy: Policy Change: MPSSVC Rule-Level Policy Change to 'No Auditing'" >> audit.txt
$a = " Policy Change: MPSSVC Rule-Level Policy Change-----------> "
$b = auditpol /get /category:* | findstr /i /c:"MPSSVC Rule-Level Policy Change"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.47 Set 'Audit Policy: Policy Change: Other Policy Change Events' to 'No Auditing'" 
echo "Audit Policy: Policy Change: Other Policy Change Events to 'No Auditing'" >> audit.txt
$a = " Policy Change: Other Policy Change Events-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Other Policy Change Events"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.48 Set 'Audit Policy: Privilege Use: Non Sensitive Privilege Use' to 'No Auditing'" 
echo "Audit Policy: Privilege Use: Non Sensitive Privilege Use to 'No Auditing'" >> audit.txt
$a = "Privilege Use: Non Sensitive Privilege Use -----------> "
$b = auditpol /get /category:* | findstr /i /c:"Non Sensitive Privilege Use"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.49 Set 'Audit Policy: Privilege Use: Other Privilege Use Events' to 'No Auditing'" 
echo "Audit Policy: Privilege Use: Other Privilege Use Events to 'No Auditing'" >> audit.txt
$a = "Privilege Use: Other Privilege Use Events -----------> "
$b = auditpol /get /category:* | findstr /i /c:"Other Privilege Use Events"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.50 Set 'Audit Policy: Privilege Use: Sensitive Privilege Use' to 'Success and Failure'" 
echo "Audit Policy: Privilege Use: Sensitive Privilege Use to 'No Auditing'" >> audit.txt
$a = "Privilege Use: Sensitive Privilege Use -----------> "
$b = auditpol /get /category:* | findstr /i /c:"Sensitive Privilege Use"
$a += if ($b -match "Success and Failure") {echo "compliance"} else {echo "Non compliance this value should be Success and Failure"}
write-output $a
echo "1.1.2.51 Set 'Audit Policy: System: IPsec Driver' to 'Success and Failure'" 
echo "Audit Policy: System: IPsec Driver' to 'Success and Failure'" >> audit.txt
$a = "System: IPsec Driver -----------> "
$b = auditpol /get /category:* | findstr /i /c:"IPsec Driver"
$a += if ($b -match "Success and Failure") {echo "compliance"} else {echo "Non compliance this value should be Success and Failure"}
write-output $a
echo "1.1.2.52 Set 'Audit Policy: System: Other System Events' to 'No Auditing'" 
echo "Audit Policy: System: Other System Events' to ''No Auditing'" >> audit.txt
$a = "System: Other System Events>----------->> "
$b = auditpol /get /category:* | findstr /i /c:"Other System Events"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.53 Set 'Audit Policy: System: Security State Change' to 'Success and Failure'" 
echo "Audit Policy: System: Security State Change' to 'Success and Failure'" >> audit.txt
$a = "System: Security State Change-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Other System Events"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.54 Set 'Audit Policy: System: Security System Extension' to 'Success and Failure'" 
echo "Audit Policy: System: Security System Extension' to 'Success and Failure'" >> audit.txt
$a = "System: Security System Extension-----------> "
$b = auditpol /get /category:* | findstr /i /c:"Security System Extension"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.2.55 Set 'Audit Policy: System: System Integrity' to 'Success and Failure'" 
echo "Audit Policy: System: System Integrity' to 'Success and Failure'" >> audit.txt
$a = "System: System Integrity>----------->> "
$b = auditpol /get /category:* | findstr /i /c:"System Integrity"
$a += if ($b -match "No Auditing") {echo "compliance"} else {echo "Non compliance this value should be No Auditing"}
write-output $a
echo "1.1.3 Security Options"
echo "Major 1.1.3 Security Options" >> audit.txt
echo ""Minor 1.1.3.1 Accounts" >> audit.txt

echo "Checking for Security Options"


echo "1.1.3.1.1 Configure 'Accounts: Rename administrator account'" 
echo "Configure 'Accounts: Rename administrator account''" >> audit.txt
$a = "Rename administrator account-----------> "
$b = net user | findstr /i "administrator"
$a += if ($b -match "Administrator" ) {echo "Non compliance Administartor account should be rename"} else {echo "compliance"}
write-output $a


echo "1.1.3.1.2 Configure 'Accounts: Rename guest account'" 
echo "Configure 'Accounts: Rename guest account'" >> audit.txt
$a = "Rename administrator account-----------> "
$b = net user | findstr /i "guest"
$a += if ($b -match "Guest" ) {echo "Non compliance Guest account should be rename"} else {echo "compliance"}
write-output $a

echo "1.1.3.1.3 Set 'Accounts: Limit local account use of blank passwords to console logon only' to 'Enabled'" 
echo "Limit local account use of blank passwords to console logon only' to 'Enabled'" >> audit.txt
$a = "Limit local account use of blank passwords-----------> "
$b = reg query HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\LSA | findstr /i "limit"
$a += if ($b -match "0x1" ) {echo "compliance"} else {echo "Non compliance "}
write-output $a

echo "1.1.3.2.1 Configure 'Audit: Audit the access of global system objects'" 
echo " access of global system objects" >> audit.txt
$a = "access of global system objects-----------> "
$b = reg query HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\LSA | findstr /i "auditbaseobjects"
$a += if ($b -match "0x1" ) {echo "compliance"} else {echo "Non compliance"}
write-output $a

echo "1.1.3.2.2 Configure 'Audit: Audit the use of Backup and Restore privilege'" 
echo "Audit the use of Backup and Restore privilege" >> audit.txt
$a = "use of Backup and Restore privilege-----------> "
$b = reg query HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\LSA | findstr /i "fullprivilegeauditing"
$a += if ($b -match 1 ) {echo "compliance"} else {echo "Non compliance"}
write-output $a

echo "1.1.3.2.3 Set 'Audit: Force audit policy subcategory settings to override audit policy category settings' to 'Enabled'" 
echo "Force audit policy subcategory settings to override audit policy category settings" >> audit.txt
$a = "Force audit policy subcategory settings to override audit policy category settings-----------> "
$b = reg query HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\LSA | findstr /i "scenoapplylegacyauditpolicy"
$a += if ($b -match "0x1" ) {echo "compliance"} else {echo "Non compliance"}
write-output $a

echo "1.1.3.2.4 Set 'Audit: Shut down system immediately if unable to log security audits' to 'Disabled'" 
echo "Shut down system immediately if unable to log security audits" >> audit.txt
$a = "Shut down system immediately if unable to log security audits-----------> "
$b = reg query HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\LSA | findstr /i "crashonauditfail"
$a += if ($b -match "0x0" ) {echo "compliance"} else {echo "Non compliance"}
write-output $a

echo "1.1.3.4.5 Set 'Devices: Prevent users from installing printer drivers' to 'Enabled'" 
echo "prevent users from installing printer drivers" >> audit.txt
$a = "prevent users from installing printer drivers-----------> "
$b = reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" | findstr /i "AddPrinterDriver"
$a += if ($b -match "0x1" ) {echo "compliance"} else {echo "Non compliance"}
write-output $a

#echo "1.1.3.5.1 Set 'Domain controller: Allow server operators to schedule tasks' to 'Disabled'" 
#echo "Allow server operators to schedule tasks" >> audit.txt
#$a = "Allow server operators to schedule tasks-----------> "
#$b = reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" | findstr /i "AddPrinterDriver"
#$a += if ($b -match "0x1" ) {echo "compliance"} else {echo "Non compliance"}
#write-output $a

#echo "1.1.3.5.2 Set 'Domain controller: LDAP server signing requirements' to 'Require signing'" 
#echo "Domain controller: LDAP server signing requirements' to 'Require signing'" >> audit.txt
#$a = "LDAP server signing requirements-----------> "
#$b = reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" | findstr /i "AddPrinterDriver"
#$a += if ($b -match "0x1" ) {echo "compliance"} else {echo "Non compliance"}
#write-output $a


echo "1.1.3.5.3 Set 'Domain controller: Refuse machine account password changes' to 'Disabled'" 
echo "'Domain controller: Refuse machine account password changes' to 'Disabled'" >> audit.txt
$a = "Refuse machine account password changes-----------> "
$b = reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" | findstr /i "Disable"
$a += if ($b -match "0x1" ) {echo "compliance"} else {echo "Non compliance"}
write-output $a

echo "1.1.3.6.1 Set 'Domain member: Digitally encrypt or sign secure channel data (always)' to 'Enabled'" 
echo "Domain member: Digitally encrypt or sign secure channel data" >> audit.txt
$a = "Digitally encrypt or sign secure channel data-----------> "
$b = reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" | findstr /i "SignOnSeal"
$a += if ($b -match "0x1" ) {echo "compliance"} else {echo "Non compliance"}
write-output $a

echo "1.1.3.6.2 Set 'Domain member: Digitally encrypt secure channel data (when possible)' to 'Enabled'" 
echo "Domain member: Digitally encrypt secure channel data " >> audit.txt
$a = " Digitally encrypt secure channel data -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" | findstr /i "sealsecure"
$a += if ($b -match "0x1" ) {echo "compliance"} else {echo "Non compliance"}
write-output $a

echo "1.1.3.6.3 Set 'Domain member: Digitally sign secure channel data (when possible)' to 'Enabled'" 
echo "Domain member: Digitally sign secure channel data " >> audit.txt
$a = " Digitally sign secure channel data  -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" | findstr /i "signsecure"
$a += if ($b -match "0x1" ) {echo "compliance"} else {echo "Non compliance"}
write-output $a

echo "1.1.3.6.4 Set 'Domain member: Disable machine account password changes' to 'Disabled'" 
echo "Domain member: Disable machine account password changes" >> audit.txt
$a = " Disable machine account password changes  -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" | findstr /i "Disable"
$a += if ($b -match "0x1" ) {echo "compliance"} else {echo "Non compliance"}
write-output $a

echo "1.1.3.6.5 Set 'Domain member: Maximum machine account password age' to '30 or fewer day(s)'" 
echo "Domain member: Maximum machine account password age" >> audit.txt
$a = " Maximum machine account password age  -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" | findstr /i "Disable"
$a += if ($b -match 0x1e ) {echo "compliance"} else {echo "Non compliance"}
write-output $a

echo "1.1.3.6.6 Set 'Domain member: Require strong (Windows 2000 or later) session key' to 'Enabled'" 
echo "Domain member: Require strong session key" >> audit.txt
$a = " Require strong session key  -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" | findstr /i "requirestrong"
$a += if ($b -match "0x1" ) {echo "compliance"} else {echo "Non compliance"}
write-output $a

echo "1.1.3.7.1 Configure 'Interactive logon: Display user information when the session is locked'" 
echo "Interactive logon: Display user information when the session is locked'" >> audit.txt
$a = "Interactive logon: Display user information when the session is locked'  -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" | findstr /i "DontDisplaylockedUserId"
$a += if ($b -match "0x1" ) {echo "compliance"} else {echo "Non compliance"}
write-output $a

echo "1.1.3.7.2 Configure 'Interactive logon: Message text for users attempting to log on'" 
echo "Interactive logon: Message text for users attempting to log on'" >> audit.txt
$a = "Interactive logon: Message text for users attempting to log on'  -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" | findstr /i "legalnoticetext"
$a += if ($b -match "****") {echo "compliance"} else {echo "Non compliance"}
write-output $a

echo "1.1.3.7.3 Configure 'Interactive logon: Message title for users attempting to log on'" 
echo "Interactive logon: Message title for users attempting to log on" >> audit.txt
$a = "Interactive logon: Message title for users attempting to log on  -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" | findstr /i "legalnoticeCaption"
$a += if ($b -match "Warning") {echo "compliance"} else {echo "Non compliance"}
write-output $a

echo "1.1.3.7.5 Set 'Interactive logon: Do not display last user name' to 'Enabled'" 
echo "Interactive logon: Do not display last user name" >> audit.txt
$a = "Interactive logon: Do not display last user name  -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" | findstr /i "DontDisplay"
$a += if ($b -match "0x1" ) {echo "compliance"} else {echo "Non compliance"}
write-output $a

echo "1.1.3.7.6 Set 'Interactive logon: Do not require CTRL+ALT+DEL' to 'Disabled'" 
echo "Interactive logon: Do not require CTRL+ALT+DEL" >> audit.txt
$a = "Interactive logon: Do not require CTRL+ALT+DEL  -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" | findstr /i "CAD"
$a += if ($b -match "0x0" ) {echo "compliance"} else {echo "Non compliance"}
write-output $a

#echo "1.1.3.7.7 Set 'Interactive logon: Machine inactivity limit' to '900 or fewer seconds'" 
#echo "Interactive logon: Machine inactivity limit' to '900 or fewer seconds " >> audit.txt
#a = "Interactive logon: Machine inactivity limit' to '900 or fewer seconds  -----------> "
#$b = reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" | findstr /i "CAD"
#$a += if ($b -match "0x0" ) {echo "compliance"} else {echo "Non compliance"}
#write-output $a

echo "1.1.3.7.8 Set 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' to '4 or fewer logon(s)'" 
echo "Interactive logon: Number of previous logons to cache to '4 or fewer logon" >> audit.txt
$a = "Interactive logon: Number of previous logons to cache to '4 or fewer logon  -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\WinLogon"  | findstr "CachedLogonsCount"
$a += if ($b -match "4" ) {echo "compliance"} else {echo "Non compliance"}
write-output $a

echo "1.1.3.7.9 Set 'Interactive logon: Prompt user to change password before expiration' to '14 or more day(s)'" 
echo "Interactive logon: Prompt user to change password before expiration" >> audit.txt
$a = "Interactive logon: Prompt user to change password before expiration  -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\WinLogon"  | findstr /i "password"
$a += if ($b -match 0x14 ) {echo "compliance"} else {echo "Non compliance"}
write-output $a

echo "1.1.3.7.10 Set 'Interactive logon: Require Domain Controller authentication to unlock workstation' to 'Disabled'" 
echo "Interactive logon: Require Domain Controller authentication to unlock workstation" >> audit.txt
$a = "Interactive logon: Require Domain Controller authentication to unlock workstation  -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\WinLogon"  | findstr /i "ForceUnlock"
$a += if ($b -match "0x0" ) {echo "compliance"} else {echo "Non compliance"}
write-output $a

echo "1.1.3.7.11 Set 'Interactive logon: Smart card removal behavior' to 'Lock Workstation'" 
echo "Interactive logon: Smart card removal behavior' to 'Lock Workstation'" >> audit.txt
$a = "Interactive logon: Smart card removal behavior' to 'Lock Workstation'   -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\WinLogon"  | findstr /i "ForceUnlock"
$a += if ($b -match "0" ) {echo "Non compliance"} else {echo "compliance"}
write-output $a


#echo "1.1.3.7.12 Set 'Interactive logon: Machine account lockout threshold' to 10 or fewer invalid logon attempts" 
#echo "Interactive logon: Machine account lockout threshold' to 10 or fewer invalid logon attempts" >> audit.txt#
#$a = "Interactive logon: Machine account lockout threshold' to 10 or fewer invalid logon attempts  -----------> "
#$b = reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\WinLogon"  | findstr /i "ForceUnlock"
#$a += if ($b -match "0x0" ) {echo "compliance"} else {echo "Non compliance"}
#write-output $a

echo "1.1.3.8.1 Set 'Microsoft network client: Digitally sign communications (always)' to 'Enabled'" 
echo "Microsoft network client: Digitally sign communications (always)' to 'Enabled'" >> audit.txt
$a = "Microsoft network client: Digitally sign communications   -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"  | findstr /i "Require"
$a += if ($b -match "0x1" ) {echo "Non compliance"} else {echo "compliance"}
write-output $a

echo "1.1.3.8.2 Set 'Microsoft network client: Digitally sign communications (if server agrees)' to 'Enabled'" 
echo "Microsoft network client: Digitally sign communications (if server agrees) to 'Enabled'" >> audit.txt
$a = "Microsoft network client: Digitally sign communications (if server agrees)  -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"  | findstr /i "EnableSecuritySignature"
$a += if ($b -match "0x1" ) {echo "Non compliance"} else {echo "compliance"}
write-output $a

echo "1.1.3.8.3 Set 'Microsoft network client: Send unencrypted password to third-party SMB servers' to 'Disabled'" 
echo "Microsoft network client: Send unencrypted password to third-party SMB servers' to 'Disabled'" >> audit.txt
$a = "Microsoft network client: Send unencrypted password to third-party SMB servers'  -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"  | findstr /i "enableplain"
$a += if ($b -match "0x0" ) {echo "Non compliance"} else {echo "compliance"}
write-output $a

echo "1.1.3.9.2 Set 'Microsoft network server: Amount of idle time required before suspending session' to '15 or fewer minute(s)'" 
echo "Microsoft network server: Amount of idle time required before suspending session' to '15 or fewer minute(s)" >> audit.txt
$a = "Microsoft network server: Amount of idle time required before suspending session' to '15 or fewer minute(s)'  -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters"  | findstr /i "auto"
$a += if ($b -match 0xf ) {echo "Non compliance"} else {echo "compliance"}
write-output $a

echo "1.1.3.9.3 Set 'Microsoft network server: Digitally sign communications (always)' to 'Enabled'" 
echo "Microsoft network server: Digitally sign communications (always)" >> audit.txt
$a = "Microsoft network server: Digitally sign communications (always)'  -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters"  | findstr /i "require"
$a += if ($b -match "0x1" ) {echo "Non compliance"} else {echo "compliance"}
write-output $a

echo "1.1.3.9.4 Set 'Microsoft network server: Digitally sign communications (if client agrees)' to 'Enabled'" 
echo "Microsoft network server: Digitally sign communications (if client agrees)" >> audit.txt
$a = "Microsoft network server: Digitally sign communications (if client agrees)  -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters"  | findstr /i "enablesecurity"
$a += if ($b -match "0x1" ) {echo "Non compliance"} else {echo "compliance"}
write-output $a

echo "1.1.3.9.5 Set 'Microsoft network server: Disconnect clients when logon hours expire' to 'Enabled'" 
echo "Microsoft network server: Disconnect clients when logon hours expire" >> audit.txt
$a = "Microsoft network server: Disconnect clients when logon hours expire  -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters"  | findstr /i "enableforcelogoff"
$a += if ($b -match "0x1" ) {echo "Non compliance"} else {echo "compliance"}
write-output $a

echo "1.1.3.10.11 Set 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' to 'Disabled'" 
echo "MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' to 'Disabled'" >> audit.txt
$a = "MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' to 'Disabled'  -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"  | findstr /i "autoadmin"
$a += if ($b -match "0") {echo "Non compliance"} else {echo "compliance"}
write-output $a


#echo "1.1.3.10.12 Set 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' to 'Highest protection, source routing is completely disabled'" 
#echo "MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' to 'Disabled'" >> audit.txt
#$a = "MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' to 'Disabled'  -----------> "
#$b = reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"  | findstr /i "autoadmin"
#$a += if ($b -match "0") {echo "Non compliance"} else {echo "compliance"}
#write-output $a


echo "1.1.3.10.15 Set 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' to '0'" 
echo "MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)'" >> audit.txt
$a = "MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)'  -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"  | findstr /i "ScreenSaverGracePeriod"
$a += if ($b -match "5") {echo "Non compliance"} else {echo "compliance"}
write-output $a

echo "1.1.3.10.16 Set 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' to '0.9 or less'" 
echo "MSS: Percentage threshold for the security event log at which the system will generate a warning' to '0.9" >> audit.txt
$a = "MSS: Percentage threshold for the security event log at which the system will generate a warning' to '0.9  -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security"  | findstr /i "WarningLevel"
$a += if ($b -match "9") {echo "Non compliance"} else {echo "compliance"}
write-output $a

echo "1.1.3.10.16 Set 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' to '0.9 or less'" 
echo "MSS: Percentage threshold for the security event log at which the system will generate a warning' to '0.9" >> audit.txt
$a = "MSS: Percentage threshold for the security event log at which the system will generate a warning' to '0.9  -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security"  | findstr /i "WarningLevel"
$a += if ($b -match "9") {echo "Non compliance"} else {echo "compliance"}
write-output $a


#echo "1.1.3.11.4 Set 'Network access: Allow anonymous SID/Name translation' to 'Disabled'" 
#echo "Network access: Allow anonymous SID/Name translation' to 'Disabled'" >> audit.txt
#$a = "Network access: Allow anonymous SID/Name translation' to 'Disabled'  -----------> "
#$b = reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security"  | findstr /i "WarningLevel"
#$a += if ($b -match "9") {echo "Non compliance"} else {echo "compliance"}
#write-output $a

echo "1.1.3.11.5 Set 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' to 'Enabled'" 
echo "Network access:  Do not allow anonymous enumeration of SAM accounts and shares' to 'Enabled'" >> audit.txt
$a = "Network access:  Do not allow anonymous enumeration of SAM accounts and shares' to 'Enabled'  -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"  | findstr /i "restrictanonymous"
$a += if ($b -match "0x1") {echo "Non compliance"} else {echo "compliance"}
write-output $a

echo "1.1.3.11.6 Set 'Network access: Do not allow anonymous enumeration of SAM accounts' to 'Enabled'" 
echo "Network access:  Do not allow anonymous enumeration of SAM accounts' to 'Enabled'" >> audit.txt
$a = "Network access:  Do not allow anonymous enumeration of SAM accounts   -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"  | findstr /i "restrictanonymoussam"
$a += if ($b -match "0x1") {echo "Non compliance"} else {echo "compliance"}
write-output $a

echo "1.1.3.11.7 Set 'Network access: Let Everyone permissions apply to anonymous users' to 'Disabled'" 
echo "Network access: Let Everyone permissions apply to anonymous users' to 'Enabled'" >> audit.txt
$a = "Network access: Let Everyone permissions apply to anonymous users   -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"  | findstr /i "Everyone"
$a += if ($b -match "0x0") {echo "Non compliance"} else {echo "compliance"}
write-output $a

#echo "1.1.3.11.8 Set 'Network access: Remotely accessible registry paths and sub-paths' to 'System\CurrentControlSet\Control\Print\Printers System\CurrentControlSet\Services\Eventlog Software\Microsoft\OLAP Server Software\Microsoft\Windows NT\CurrentVersion\Print Softwar" 
#echo "Network access: Remotely accessible registry paths and sub-paths" >> audit.txt
#$a = "Network access: Remotely accessible registry paths and sub-paths   -----------> "
#$b = reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"  | findstr /i "Everyone"
#$a += if ($b -match "0x0") {echo "Non compliance"} else {echo "compliance"}
#write-output $a

echo "1.1.3.11.10 Set 'Network access: Restrict anonymous access to Named Pipes and Shares' to 'Enabled'"
echo "Network access: Restrict anonymous access to Named Pipes and Shares' to 'Enabled'" >> audit.txt
$a = "Network access: Restrict anonymous access to Named Pipes and Shares' to 'Enabled'   -----------> "
$b = reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"  | findstr /i " restrictnullsessaccess"
$a += if ($b -match "0x0") {echo "Non compliance"} else {echo "compliance"}
write-output $a