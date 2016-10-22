# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000122 - Windows Media Player must be configured to prevent automatic checking for updates.'

control 'WN12-CC-000122' do
  impact 0.5
  title 'Windows Media Player must be configured to prevent automatic checking for updates.'
  desc '
Uncontrolled system updates can introduce issues to a system.  The automatic check for updates performed by Windows Media Player must be disabled to ensure a constant platform and to prevent the introduction of unknown\untested software on the system.
'
  tag 'stig','WN12-CC-000122'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000122_chk'
  tag fixid: 'F-WN12-CC-000122_fix'
  tag version: 'WN12-CC-000122'
  tag ruleid: 'WN12-CC-000122_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Media Player -> "Prevent Automatic Updates" to "Enabled".

Windows Media Player is not installed by default.  If it is not installed, this is NA.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\WindowsMediaPlayer\

Value Name: DisableAutoupdate

Type: REG_DWORD
Value: 1

Windows Media Player is not installed by default.  If it is not installed, this is NA.
'

# START_DESCRIBE WN12-CC-000122
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000122

end
