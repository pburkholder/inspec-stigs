# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000058 - The system must be configured to prevent unsolicited remote assistance offers.'

control 'WN12-CC-000058' do
  impact 0.5
  title 'The system must be configured to prevent unsolicited remote assistance offers.'
  desc '
Remote assistance allows another user to view or take control of the local session of a user.  Unsolicited remote assistance is help that is offered by the remote user.  This may allow unauthorized parties access to the resources on the computer.
'
  tag 'stig','WN12-CC-000058'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000058_chk'
  tag fixid: 'F-WN12-CC-000058_fix'
  tag version: 'WN12-CC-000058'
  tag ruleid: 'WN12-CC-000058_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Remote Assistance -> "Configure Offer Remote Assistance" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: fAllowUnsolicited

Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-CC-000058
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000058

end
