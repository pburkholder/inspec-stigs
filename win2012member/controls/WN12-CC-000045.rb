# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000045 - The Windows Customer Experience Improvement Program must be disabled.'

control 'WN12-CC-000045' do
  impact 0.5
  title 'The Windows Customer Experience Improvement Program must be disabled.'
  desc '
Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting ensures the Windows Customer Experience Improvement Program is disabled so information is not passed to the vendor.
'
  tag 'stig','WN12-CC-000045'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000045_chk'
  tag fixid: 'F-WN12-CC-000045_fix'
  tag version: 'WN12-CC-000045'
  tag ruleid: 'WN12-CC-000045_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication Settings -> "Turn off Windows Customer Experience Improvement Program" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\SQMClient\Windows\

Value Name: CEIPEnable

Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-CC-000045
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000045

end
