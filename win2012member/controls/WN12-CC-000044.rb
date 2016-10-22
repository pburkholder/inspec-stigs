# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000044 - Windows Messenger must be prevented from collecting anonymous information about how the service is used.'

control 'WN12-CC-000044' do
  impact 0.5
  title 'Windows Messenger must be prevented from collecting anonymous information about how the service is used.'
  desc '
Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting prevents Windows Messenger from collecting anonymous information about how the Windows Messenger software and service is used.
'
  tag 'stig','WN12-CC-000044'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000044_chk'
  tag fixid: 'F-WN12-CC-000044_fix'
  tag version: 'WN12-CC-000044'
  tag ruleid: 'WN12-CC-000044_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings -> "Turn off the Windows Messenger Customer Experience Improvement Program" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Messenger\Client\

Value Name: CEIP

Type: REG_DWORD
Value: 2
'

# START_DESCRIBE WN12-CC-000044
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000044

end
