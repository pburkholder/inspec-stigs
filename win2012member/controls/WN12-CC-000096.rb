# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000096 - Passwords must not be saved in the Remote Desktop Client.'

control 'WN12-CC-000096' do
  impact 0.5
  title 'Passwords must not be saved in the Remote Desktop Client.'
  desc '
Saving passwords in the Remote Desktop Client could allow an unauthorized user to establish a remote desktop session to another system.  The system must be configured to prevent users from saving passwords in the Remote Desktop Client.
'
  tag 'stig','WN12-CC-000096'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000096_chk'
  tag fixid: 'F-WN12-CC-000096_fix'
  tag version: 'WN12-CC-000096'
  tag ruleid: 'WN12-CC-000096_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Connection Client -> "Do not allow passwords to be saved" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: DisablePasswordSaving

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000096
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000096

end
