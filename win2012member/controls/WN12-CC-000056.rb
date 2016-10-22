# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000056 - The display must turn off after 20 minutes of inactivity when the system is running on battery.'

control 'WN12-CC-000056' do
  impact 0.1
  title 'The display must turn off after 20 minutes of inactivity when the system is running on battery.'
  desc '
Turning off an inactive display supports energy saving initiatives.  It may also extend availability on systems running on a battery.
'
  tag 'stig','WN12-CC-000056'
  tag severity: 'low'
  tag checkid: 'C-WN12-CC-000056_chk'
  tag fixid: 'F-WN12-CC-000056_fix'
  tag version: 'WN12-CC-000056'
  tag ruleid: 'WN12-CC-000056_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Power Management -> Video and Display Settings -> "Turn off the display (on battery)" to "Enabled" with "1200" seconds or less.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Power\PowerSettings\3C0BC021-C8A8-4E07-A973-6B14CBCB2B7E\

Value Name: DCSettingIndex

Type: REG_DWORD
Value: 0x000004b0 (1200) or less

If an organization has an operational requirement to keep displays active, this would not be a finding.
'

# START_DESCRIBE WN12-CC-000056
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000056

end
