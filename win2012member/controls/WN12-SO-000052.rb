# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000052 - Anonymous enumeration of shares must be restricted.'

control 'WN12-SO-000052' do
  impact 1.0
  title 'Anonymous enumeration of shares must be restricted.'
  desc '
Allowing anonymous logon users (null session connections) to list all account names and enumerate all shared resources can provide a map of potential points to attack the system.
'
  tag 'stig','WN12-SO-000052'
  tag severity: 'high'
  tag checkid: 'C-WN12-SO-000052_chk'
  tag fixid: 'F-WN12-SO-000052_fix'
  tag version: 'WN12-SO-000052'
  tag ruleid: 'WN12-SO-000052_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Do not allow anonymous enumeration of SAM accounts and shares" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Lsa\

Value Name: RestrictAnonymous

Value Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-SO-000052
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000052

end
