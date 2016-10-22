# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-UC-000005 - Notifications from Windows Push Network Service must be turned off.'

control 'WN12-UC-000005' do
  impact 0.1
  title 'Notifications from Windows Push Network Service must be turned off.'
  desc '
The Windows Push Notification Service (WNS) allows third-party vendors to send updates for toasts, tiles, and badges.
'
  tag 'stig','WN12-UC-000005'
  tag severity: 'low'
  tag checkid: 'C-WN12-UC-000005_chk'
  tag fixid: 'F-WN12-UC-000005_fix'
  tag version: 'WN12-UC-000005'
  tag ruleid: 'WN12-UC-000005_rule'
  tag fixtext: '
Configure the policy value for User Configuration -> Administrative Templates -> Start Menu and Taskbar -> Notifications -> "Turn off notifications network usage" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\

Value Name: NoCloudApplicationNotification

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-UC-000005
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-UC-000005

end
