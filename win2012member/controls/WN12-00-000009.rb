# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-00-000009 - Members of the Backup Operators group must have separate accounts for backup duties and normal operational tasks.'

control 'WN12-00-000009' do
  impact 0.5
  title 'Members of the Backup Operators group must have separate accounts for backup duties and normal operational tasks.'
  desc '
Backup Operators are able to read and write to any file in the system, regardless of the rights assigned to it.  Backup and restore rights permit users to circumvent the file access restrictions present on NTFS disk drives for backup and restore purposes.  Members of the Backup Operators group must have separate logon accounts for performing backup duties.
'
  tag 'stig','WN12-00-000009'
  tag severity: 'medium'
  tag checkid: 'C-WN12-00-000009_chk'
  tag fixid: 'F-WN12-00-000009_fix'
  tag version: 'WN12-00-000009'
  tag ruleid: 'WN12-00-000009_rule'
  tag fixtext: '
Ensure that each member of the Backup Operators group has separate accounts for backup functions and standard user functions.  Create the necessary documentation that identifies the members of the Backup Operators group.
'
  tag checktext: '
Review the Backup Operators group in Computer Management or Active Directory Users and Computers.  

If the group contains any accounts, including application accounts, this must be documented with the IAO.  

Any accounts that are members of the Backup Operators group must be documented, including application accounts.  Users with accounts in the Backup Operators group must have a separate user account for backup functions and for performing normal user tasks.

If the group contains no accounts, this is not a finding.
If users with accounts in the Backup Operators group do not have separate accounts for backup functions and standard user functions, this is a finding.
'

# START_DESCRIBE WN12-00-000009
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-00-000009

end
