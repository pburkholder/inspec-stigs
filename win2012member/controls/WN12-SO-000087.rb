# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000087 - Software certificate restriction policies must be enforced.'

control 'WN12-SO-000087' do
  impact 0.5
  title 'Software certificate restriction policies must be enforced.'
  desc '
Software restriction policies help to protect users and computers from executing unauthorized code such as viruses and Trojans horses.  This setting must be enabled to enforce certificate rules in software restriction policies.
'
  tag 'stig','WN12-SO-000087'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000087_chk'
  tag fixid: 'F-WN12-SO-000087_fix'
  tag version: 'WN12-SO-000087'
  tag ruleid: 'WN12-SO-000087_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\

Value Name: AuthenticodeEnabled

Value Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-SO-000087
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000087

end
