# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000057 - The display must turn off after 20 minutes of inactivity when the system is plugged in.'

control 'WN12-CC-000057' do
  impact 0.1
  title 'The display must turn off after 20 minutes of inactivity when the system is plugged in.'
  desc '
Turning off an inactive display supports energy saving initiatives.
'
  tag 'stig','WN12-CC-000057'
  tag severity: 'low'
  tag checkid: 'C-WN12-CC-000057_chk'
  tag fixid: 'F-WN12-CC-000057_fix'
  tag version: 'WN12-CC-000057'
  tag ruleid: 'WN12-CC-000057_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Power Management -> Video and Display Settings -> "Turn off the display (plugged in)" to "Enabled" with "1200" seconds or less.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Power\PowerSettings\3C0BC021-C8A8-4E07-A973-6B14CBCB2B7E\

Value Name: ACSettingIndex

Type: REG_DWORD
Value: 0x000004b0 (1200) or less

If an organization has an operational requirement to keep displays active, this would not be a finding.
'

# START_DESCRIBE WN12-CC-000057
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000057

end
