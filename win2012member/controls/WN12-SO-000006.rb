# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000006 - The built-in guest account must be renamed.'

control 'WN12-SO-000006' do
  impact 0.5
  title 'The built-in guest account must be renamed.'
  desc '
The built-in guest account is a well-known user account on all Windows systems and, as initially installed, does not require a password.  This can allow access to system resources by unauthorized users.  Renaming this account to an unidentified name improves the protection of this account and the system.
'
  tag 'stig','WN12-SO-000006'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000006_chk'
  tag fixid: 'F-WN12-SO-000006_fix'
  tag version: 'WN12-SO-000006'
  tag ruleid: 'WN12-SO-000006_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Accounts: Rename guest account" to a name other than "Guest".
'
  tag checktext: '
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options.

If the value for "Accounts: Rename guest account" is not set to a value other than "Guest", this is a finding.
'

# START_DESCRIBE WN12-SO-000006
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000006

end
