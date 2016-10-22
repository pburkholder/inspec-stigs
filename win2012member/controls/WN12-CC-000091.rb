# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000091 - File Explorer shell protocol must run in protected mode.'

control 'WN12-CC-000091' do
  impact 0.5
  title 'File Explorer shell protocol must run in protected mode.'
  desc '
The shell protocol will  limit the set of folders applications can open when run in protected mode.  Restricting files an application can open to a limited set of folders increases the security of Windows.
'
  tag 'stig','WN12-CC-000091'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000091_chk'
  tag fixid: 'F-WN12-CC-000091_fix'
  tag version: 'WN12-CC-000091'
  tag ruleid: 'WN12-CC-000091_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> File Explorer -> "Turn off shell protocol protected mode" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\

Value Name: PreXPSP2ShellProtocolBehavior

Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-CC-000091
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000091

end
