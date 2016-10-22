# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-UC-000003 - The screen saver must be password protected.'

control 'WN12-UC-000003' do
  impact 0.5
  title 'The screen saver must be password protected.'
  desc '
Unattended systems are susceptible to unauthorized use and must be locked when unattended.  Enabling a password-protected screen saver to engage after a specified period of time helps protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer.
'
  tag 'stig','WN12-UC-000003'
  tag severity: 'medium'
  tag checkid: 'C-WN12-UC-000003_chk'
  tag fixid: 'F-WN12-UC-000003_fix'
  tag version: 'WN12-UC-000003'
  tag ruleid: 'WN12-UC-000003_rule'
  tag fixtext: '
Configure the policy value for User Configuration -> Administrative Templates -> Control Panel -> Personalization -> "Password protect the screen saver" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \Software\Policies\Microsoft\Windows\Control Panel\Desktop\

Value Name: ScreenSaverIsSecure

Type: REG_SZ
Value: 1
'

# START_DESCRIBE WN12-UC-000003
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-UC-000003

end
