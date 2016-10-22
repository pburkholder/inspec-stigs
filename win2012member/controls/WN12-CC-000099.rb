# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000099 - Remote Desktop Services must always prompt a client for passwords upon connection.'

control 'WN12-CC-000099' do
  impact 0.5
  title 'Remote Desktop Services must always prompt a client for passwords upon connection.'
  desc '
This setting controls the ability of users to supply passwords automatically as part of their remote desktop connection.  Disabling this setting would allow anyone to use the stored credentials in a connection item to connect to the terminal server.
'
  tag 'stig','WN12-CC-000099'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000099_chk'
  tag fixid: 'F-WN12-CC-000099_fix'
  tag version: 'WN12-CC-000099'
  tag ruleid: 'WN12-CC-000099_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security -> "Always prompt for password upon connection" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: fPromptForPassword

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000099
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000099

end
