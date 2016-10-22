# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000043 - The file and folder Publish to Web option must be unavailable in Windows folders.'

control 'WN12-CC-000043' do
  impact 0.5
  title 'The file and folder Publish to Web option must be unavailable in Windows folders.'
  desc '
Allowing the option to publish to the web from File and Folder tasks in Windows folders could allow sensitive information to be exposed.
'
  tag 'stig','WN12-CC-000043'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000043_chk'
  tag fixid: 'F-WN12-CC-000043_fix'
  tag version: 'WN12-CC-000043'
  tag ruleid: 'WN12-CC-000043_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings -> "Turn off the "Publish to Web" task for files and folders" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\

Value Name: NoPublishingWizard

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000043
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000043

end
