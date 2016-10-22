# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000019 - The Ctrl+Alt+Del security attention sequence for logons must be enabled.'

control 'WN12-SO-000019' do
  impact 0.5
  title 'The Ctrl+Alt+Del security attention sequence for logons must be enabled.'
  desc '
Disabling the Ctrl+Alt+Del security attention sequence can compromise system security.  Because only Windows responds to the Ctrl+Alt+Del security sequence, a user can be assured that any passwords entered following that sequence are sent only to Windows.  If the sequence requirement is eliminated, malicious programs can request and receive a user\'s Windows password.  Disabling this sequence also suppresses a custom logon banner.
'
  tag 'stig','WN12-SO-000019'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000019_chk'
  tag fixid: 'F-WN12-SO-000019_fix'
  tag version: 'WN12-SO-000019'
  tag ruleid: 'WN12-SO-000019_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Interactive Logon: Do not require CTRL+ALT+DEL" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: DisableCAD

Value Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-SO-000019
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000019

end
