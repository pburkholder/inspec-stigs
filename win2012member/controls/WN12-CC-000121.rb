# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000121 - Users must not be presented with Privacy and Installation options on first use of Windows Media Player.'

control 'WN12-CC-000121' do
  impact 0.1
  title 'Users must not be presented with Privacy and Installation options on first use of Windows Media Player.'
  desc '
Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting prevents users from being presented with Privacy and Installation options on first use of Windows Media Player, which could enable some communication with the vendor.
'
  tag 'stig','WN12-CC-000121'
  tag severity: 'low'
  tag checkid: 'C-WN12-CC-000121_chk'
  tag fixid: 'F-WN12-CC-000121_fix'
  tag version: 'WN12-CC-000121'
  tag ruleid: 'WN12-CC-000121_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Media Player -> "Do Not Show First Use Dialog Boxes" to "Enabled".

Windows Media Player is not installed by default.  If it is not installed, this is NA.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\WindowsMediaPlayer\

Value Name: GroupPrivacyAcceptance

Type: REG_DWORD
Value: 1

Windows Media Player is not installed by default.  If it is not installed, this is NA.
'

# START_DESCRIBE WN12-CC-000121
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000121

end
