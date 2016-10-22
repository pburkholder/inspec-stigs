# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000077 - The system must require username and password to elevate a running application.'

control 'WN12-CC-000077' do
  impact 0.5
  title 'The system must require username and password to elevate a running application.'
  desc '
Enumeration of administrator accounts when elevating can provide part of the logon information to an unauthorized user.  This setting configures the system to always require users to type in a username and password to elevate a running application.
'
  tag 'stig','WN12-CC-000077'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000077_chk'
  tag fixid: 'F-WN12-CC-000077_fix'
  tag version: 'WN12-CC-000077'
  tag ruleid: 'WN12-CC-000077_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Credential User Interface -> "Enumerate administrator accounts on elevation" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\CredUI

Value Name: EnumerateAdministrators

Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-CC-000077
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000077

end
