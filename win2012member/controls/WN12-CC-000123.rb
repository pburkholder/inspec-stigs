# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000123 - The Windows Remote Management (WinRM) client must not use Basic authentication.'

control 'WN12-CC-000123' do
  impact 1.0
  title 'The Windows Remote Management (WinRM) client must not use Basic authentication.'
  desc '
Basic authentication uses plain text passwords that could be used to compromise a system.
'
  tag 'stig','WN12-CC-000123'
  tag severity: 'high'
  tag checkid: 'C-WN12-CC-000123_chk'
  tag fixid: 'F-WN12-CC-000123_fix'
  tag version: 'WN12-CC-000123'
  tag ruleid: 'WN12-CC-000123_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Client -> "Allow Basic authentication" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\WinRM\Client\

Value Name: AllowBasic

Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-CC-000123
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000123

end
