# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-UC-000004 - Changing the screen saver must be prevented.'

control 'WN12-UC-000004' do
  impact 0.1
  title 'Changing the screen saver must be prevented.'
  desc '
Unattended systems are susceptible to unauthorized use and must be locked.  Preventing users from changing the screen saver ensures an approved screen saver is used.  This protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer.
'
  tag 'stig','WN12-UC-000004'
  tag severity: 'low'
  tag checkid: 'C-WN12-UC-000004_chk'
  tag fixid: 'F-WN12-UC-000004_fix'
  tag version: 'WN12-UC-000004'
  tag ruleid: 'WN12-UC-000004_rule'
  tag fixtext: '
Configure the policy value for User Configuration -> Administrative Templates -> Control Panel -> Personalization -> "Prevent changing screen saver" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: NoDispScrSavPage

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-UC-000004
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-UC-000004

end
