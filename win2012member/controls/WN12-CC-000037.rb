# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000037 - Web publishing and online ordering wizards must be prevented from downloading a list of providers.'

control 'WN12-CC-000037' do
  impact 0.5
  title 'Web publishing and online ordering wizards must be prevented from downloading a list of providers.'
  desc '
Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting prevents Windows from downloading a list of providers for the Web publishing and online ordering wizards.
'
  tag 'stig','WN12-CC-000037'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000037_chk'
  tag fixid: 'F-WN12-CC-000037_fix'
  tag version: 'WN12-CC-000037'
  tag ruleid: 'WN12-CC-000037_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings -> "Turn off Internet download for Web publishing and online ordering wizards" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\

Value Name: NoWebServices

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000037
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000037

end
