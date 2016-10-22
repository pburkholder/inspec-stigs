# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000004 - Local accounts with blank passwords must be restricted to prevent access from the network.'

control 'WN12-SO-000004' do
  impact 1.0
  title 'Local accounts with blank passwords must be restricted to prevent access from the network.'
  desc '
An account without a password can allow unauthorized access to a system as only the username would be required.  Password policies should prevent accounts with blank passwords from existing on a system.  However, if a local account with a blank password did exist, enabling this setting will prevent network access, limiting the account to local console logon only.
'
  tag 'stig','WN12-SO-000004'
  tag severity: 'high'
  tag checkid: 'C-WN12-SO-000004_chk'
  tag fixid: 'F-WN12-SO-000004_fix'
  tag version: 'WN12-SO-000004'
  tag ruleid: 'WN12-SO-000004_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Accounts: Limit local account use of blank passwords to console logon only" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Lsa

Value Name: LimitBlankPasswordUse

Value Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-SO-000004
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000004

end
