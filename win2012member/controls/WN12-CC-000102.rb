# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000102 - Remote Desktop Services must be configured to set a time limit for disconnected sessions.'

control 'WN12-CC-000102' do
  impact 0.5
  title 'Remote Desktop Services must be configured to set a time limit for disconnected sessions.'
  desc '
This setting controls how long a session will remain open if it is unexpectedly terminated.  Such sessions use system resources and must be terminated as soon as possible.
'
  tag 'stig','WN12-CC-000102'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000102_chk'
  tag fixid: 'F-WN12-CC-000102_fix'
  tag version: 'WN12-CC-000102'
  tag ruleid: 'WN12-CC-000102_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Session Time Limits -> "Set time limit for disconnected sessions" to "Enabled", and "End a disconnected session" to "1 minute".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: MaxDisconnectionTime

Type: REG_DWORD
Value: 0x0000ea60 (60000)
'

# START_DESCRIBE WN12-CC-000102
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000102

end
