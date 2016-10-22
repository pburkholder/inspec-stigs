# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000101 - Remote Desktop Services must be configured to disconnect an idle session after the specified time period.'

control 'WN12-CC-000101' do
  impact 0.5
  title 'Remote Desktop Services must be configured to disconnect an idle session after the specified time period.'
  desc '
This setting controls how long a session may be idle before it is automatically disconnected from the server.  Users must disconnect if they plan on being away from their terminals for extended periods of time.  Idle sessions must be disconnected after 15 minutes.
'
  tag 'stig','WN12-CC-000101'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000101_chk'
  tag fixid: 'F-WN12-CC-000101_fix'
  tag version: 'WN12-CC-000101'
  tag ruleid: 'WN12-CC-000101_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Session Time Limits -> "Set time limit for active but idle Remote Desktop Services sessions" to "Enabled", and the "Idle session limit" to 15 minutes or less, excluding "0", which equates to "Never".
'
  tag checktext: '
If the following registry value does not exist or its value is set to "0" or greater than "15" minutes, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: MaxIdleTime

Type: REG_DWORD
Value: 0x000dbba0 (900000) or less but not 0
'

# START_DESCRIBE WN12-CC-000101
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000101

end
