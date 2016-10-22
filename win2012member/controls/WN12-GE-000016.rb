# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-GE-000016 - System mechanisms must be implemented to enforce automatic expiration of passwords.'

control 'WN12-GE-000016' do
  impact 0.5
  title 'System mechanisms must be implemented to enforce automatic expiration of passwords.'
  desc '
Passwords that do not expire or are reused increase the exposure of a password with greater probability of being discovered or cracked.
'
  tag 'stig','WN12-GE-000016'
  tag severity: 'medium'
  tag checkid: 'C-WN12-GE-000016_chk'
  tag fixid: 'F-WN12-GE-000016_fix'
  tag version: 'WN12-GE-000016'
  tag ruleid: 'WN12-GE-000016_rule'
  tag fixtext: '
Configure all passwords to expire.  Ensure "Password never expires" is not checked on any accounts.  Document any exceptions with the IAO.
'
  tag checktext: '
Run the DUMPSEC utility.
Select "Dump Users as Table" from the "Report" menu.
Select the following fields, and click "Add" for each entry:

UserName
SID
PswdExpires
AcctDisabled
Groups

If any accounts have "No" in the "PswdExpires" column, this is a finding. 

The following are exempt from this requirement:
Application Accounts
Domain accounts requiring smart card (CAC/PIV)

The following PowerShell command may be used on domain controllers to list inactive accounts:
Search-ADAccount -PasswordNeverExpires -UsersOnly

Accounts that meet the requirements for allowable exceptions must be documented with the IAO.
'

# START_DESCRIBE WN12-GE-000016
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-GE-000016

end
