# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000026 - Users must not be prompted to search Windows Update for device drivers.'

control 'WN12-CC-000026' do
  impact 0.1
  title 'Users must not be prompted to search Windows Update for device drivers.'
  desc '
Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting prevents users from being prompted to search Windows Update for device drivers.
'
  tag 'stig','WN12-CC-000026'
  tag severity: 'low'
  tag checkid: 'C-WN12-CC-000026_chk'
  tag fixid: 'F-WN12-CC-000026_fix'
  tag version: 'WN12-CC-000026'
  tag ruleid: 'WN12-CC-000026_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Driver Installation -> "Turn off Windows Update device driver search prompt" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\DriverSearching\

Value Name: DontPromptForWindowsUpdate

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000026
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000026

end
