# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000020 - An error report must not be sent when a generic device driver is installed.'

control 'WN12-CC-000020' do
  impact 0.1
  title 'An error report must not be sent when a generic device driver is installed.'
  desc '
Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting prevents an error report from being sent when a generic device driver is installed.
'
  tag 'stig','WN12-CC-000020'
  tag severity: 'low'
  tag checkid: 'C-WN12-CC-000020_chk'
  tag fixid: 'F-WN12-CC-000020_fix'
  tag version: 'WN12-CC-000020'
  tag ruleid: 'WN12-CC-000020_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation -> "Do not send a Windows error report when a generic driver is installed on a device" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\DeviceInstall\Settings\

Value Name: DisableSendGenericDriverNotFoundToWER

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000020
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000020

end
