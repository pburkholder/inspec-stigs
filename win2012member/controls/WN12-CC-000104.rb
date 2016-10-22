# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000104 - Remote Desktop Services must be configured to use session-specific temporary folders.'

control 'WN12-CC-000104' do
  impact 0.5
  title 'Remote Desktop Services must be configured to use session-specific temporary folders.'
  desc '
If a communal temporary folder is used for remote desktop sessions, it might be possible for users to access other users\' temporary folders.  If this setting is enabled, only one temporary folder is used for all remote desktop sessions.  Per session temporary folders must be established.
'
  tag 'stig','WN12-CC-000104'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000104_chk'
  tag fixid: 'F-WN12-CC-000104_fix'
  tag version: 'WN12-CC-000104'
  tag ruleid: 'WN12-CC-000104_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Temporary Folders -> "Do not use temporary folders per session" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: PerSessionTempDir

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000104
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000104

end
