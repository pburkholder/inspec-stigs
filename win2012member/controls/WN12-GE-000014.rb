# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-GE-000014 - Outdated or unused accounts must be removed from the system.'

control 'WN12-GE-000014' do
  impact 0.1
  title 'Outdated or unused accounts must be removed from the system.'
  desc '
Outdated or unused accounts provide penetration points that may go undetected.  Inactive accounts must be deleted if no longer necessary or, if still required, disabled until needed.
'
  tag 'stig','WN12-GE-000014'
  tag severity: 'low'
  tag checkid: 'C-WN12-GE-000014_chk'
  tag fixid: 'F-WN12-GE-000014_fix'
  tag version: 'WN12-GE-000014'
  tag ruleid: 'WN12-GE-000014_rule'
  tag fixtext: '
Regularly review accounts to determine if they are still active.  Remove or disable accounts that have not been used in the last 35 days.
'
  tag checktext: '
Run the DUMPSEC utility.
Select "Dump Users as Table" from the "Report" menu.
Select the following fields, and click "Add" for each entry:

UserName
SID
LastLogonTime
AcctDisabled

Review the "LastLogonTime".  
If any enabled accounts have not been logged into within the past 35 days, this is a finding.    

The following accounts are exempt:
Built-in administrator account (SID ending in 500)
Built-in guest account (SID ending in 501)
Application accounts
Disabled accounts

The following PowerShell command may be used on domain controllers to list inactive accounts:
Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 35.00:00:00

Review the list to determine the validity for each account reported.

Dormant accounts that have been reviewed and deemed to be required must be documented with the IAO.
'

# START_DESCRIBE WN12-GE-000014
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-GE-000014

end
