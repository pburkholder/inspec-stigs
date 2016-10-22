# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000047 - Windows must be prevented from using Windows Update to search for drivers.'

control 'WN12-CC-000047' do
  impact 0.5
  title 'Windows must be prevented from using Windows Update to search for drivers.'
  desc '
Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting prevents Windows from searching Windows Update for device drivers when no local drivers for a device are present.
'
  tag 'stig','WN12-CC-000047'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000047_chk'
  tag fixid: 'F-WN12-CC-000047_fix'
  tag version: 'WN12-CC-000047'
  tag ruleid: 'WN12-CC-000047_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings -> "Turn off Windows Update device driver searching" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\DriverSearching\

Value Name: DontSearchWindowsUpdate

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000047
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000047

end
