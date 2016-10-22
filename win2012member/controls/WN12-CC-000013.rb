# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000013 - The Windows Connect Now wizards must be disabled.'

control 'WN12-CC-000013' do
  impact 0.5
  title 'The Windows Connect Now wizards must be disabled.'
  desc '
Windows Connect Now provides wizards for tasks such as "Set up a wireless router or access point" and must not be available to users.  Functions such as these may allow unauthorized connections to a system and the potential for sensitive information to be compromised.
'
  tag 'stig','WN12-CC-000013'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000013_chk'
  tag fixid: 'F-WN12-CC-000013_fix'
  tag version: 'WN12-CC-000013'
  tag ruleid: 'WN12-CC-000013_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Windows Connect Now -> "Prohibit Access of the Windows Connect Now wizards" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\WCN\UI\

Value Name: DisableWcnUi

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000013
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000013

end
