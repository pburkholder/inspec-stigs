# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000117 - Users must be notified if a web-based program attempts to install software.'

control 'WN12-CC-000117' do
  impact 0.5
  title 'Users must be notified if a web-based program attempts to install software.'
  desc '
Users must be aware of attempted program installations.  This setting ensures users are notified if a web-based program attempts to install software.
'
  tag 'stig','WN12-CC-000117'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000117_chk'
  tag fixid: 'F-WN12-CC-000117_fix'
  tag version: 'WN12-CC-000117'
  tag ruleid: 'WN12-CC-000117_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer -> "Prevent Internet Explorer security prompt for Windows Installer scripts" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\Installer\

Value Name: SafeForScripting

Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-CC-000117
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000117

end
