# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000076 - The password reveal button must not be displayed.'

control 'WN12-CC-000076' do
  impact 0.5
  title 'The password reveal button must not be displayed.'
  desc '
Visible passwords may be seen by nearby persons, compromising them.   The password reveal button can be used to display an entered password and must not be allowed.
'
  tag 'stig','WN12-CC-000076'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000076_chk'
  tag fixid: 'F-WN12-CC-000076_fix'
  tag version: 'WN12-CC-000076'
  tag ruleid: 'WN12-CC-000076_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Credential User Interface -> "Do not display the password reveal button" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\CredUI\

Value Name: DisablePasswordReveal

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000076
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000076

end
