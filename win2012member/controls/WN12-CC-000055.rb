# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000055 - The user must be prompted for a password on resume from sleep (plugged in).'

control 'WN12-CC-000055' do
  impact 0.5
  title 'The user must be prompted for a password on resume from sleep (plugged in).'
  desc '
Authentication must always be required when accessing a system.  This setting ensures the user is prompted for a password on resume from sleep (plugged in).
'
  tag 'stig','WN12-CC-000055'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000055_chk'
  tag fixid: 'F-WN12-CC-000055_fix'
  tag version: 'WN12-CC-000055'
  tag ruleid: 'WN12-CC-000055_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Power Management -> Sleep Settings -> "Require a password when a computer wakes (plugged in)" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\

Value Name: ACSettingIndex

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000055
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000055

end
