# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000052 - App notifications on the lock screen must be turned off.'

control 'WN12-CC-000052' do
  impact 0.5
  title 'App notifications on the lock screen must be turned off.'
  desc '
App notifications that are displayed on the lock screen could display sensitive information to unauthorized personnel.  Turning off this feature will limit access to the information to a logged on user.
'
  tag 'stig','WN12-CC-000052'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000052_chk'
  tag fixid: 'F-WN12-CC-000052_fix'
  tag version: 'WN12-CC-000052'
  tag ruleid: 'WN12-CC-000052_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Logon -> "Turn off app notifications on the lock screen" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\System\

Value Name: DisableLockScreenAppNotifications

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000052
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000052

end
