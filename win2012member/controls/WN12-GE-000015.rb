# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-GE-000015 - Accounts must require passwords.'

control 'WN12-GE-000015' do
  impact 1.0
  title 'Accounts must require passwords.'
  desc '
The lack of password protection enables anyone to gain access to the information system, which opens a backdoor opportunity for intruders to compromise the system as well as other resources.  Accounts on a system must require passwords.
'
  tag 'stig','WN12-GE-000015'
  tag severity: 'high'
  tag checkid: 'C-WN12-GE-000015_chk'
  tag fixid: 'F-WN12-GE-000015_fix'
  tag version: 'WN12-GE-000015'
  tag ruleid: 'WN12-GE-000015_rule'
  tag fixtext: '
Ensure all accounts are configured to require passwords to gain access.

The password required flag can be set by entering the following on a command line: "Net user <account_name> /passwordreq:yes".
'
  tag checktext: '
Verify all accounts require passwords.

Run the DUMPSEC utility.
Select "Dump Users as Table" from the "Report" menu.
Select the following fields, and click "Add" for each entry:

UserName
SID
PswdRequired
AcctDisabled
Groups

If any accounts have "No" in the "PswdRequired" column, this is a finding.

Some built-in or application-generated accounts (e.g., Guest, IWAM_, IUSR, etc.) may not have this flag set, even though there are passwords present.  It can be set by entering the following on a command line: "Net user <account_name> /passwordreq:yes".
'

# START_DESCRIBE WN12-GE-000015
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-GE-000015

end
