# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000103 - Remote Desktop Services must delete temporary folders when a session is terminated.'

control 'WN12-CC-000103' do
  impact 0.5
  title 'Remote Desktop Services must delete temporary folders when a session is terminated.'
  desc '
Remote desktop session temporary folders must always be deleted after a session is over to prevent hard disk clutter and potential leakage of information.  This setting controls the deletion of the temporary folders when the session is terminated.
'
  tag 'stig','WN12-CC-000103'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000103_chk'
  tag fixid: 'F-WN12-CC-000103_fix'
  tag version: 'WN12-CC-000103'
  tag ruleid: 'WN12-CC-000103_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Temporary Folders -> "Do not delete temp folder upon exit" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: DeleteTempDirsOnExit

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000103
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000103

end
