# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-FW-000018 - The Windows Firewall must log successful connections for the Private Profile.'

control 'WN12-FW-000018' do
  impact 0.1
  title 'The Windows Firewall must log successful connections for the Private Profile.'
  desc '
A firewall provides a line of defense against attack.  To be effective, it must be enabled and properly configured.  Logging of successful connections for a private network connection will be enabled  to maintain an audit trail if issues are discovered.
'
  tag 'stig','WN12-FW-000018'
  tag severity: 'low'
  tag checkid: 'C-WN12-FW-000018_chk'
  tag fixid: 'F-WN12-FW-000018_fix'
  tag version: 'WN12-FW-000018'
  tag ruleid: 'WN12-FW-000018_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Windows Firewall with Advanced Security -> Windows Firewall with Advanced Security -> Windows Firewall Properties (this link will be in the right pane) -> Private Profile Tab -> Logging (select Customize), "Logged successful connections" to "Yes".

Configure a comparable setting if a third-party firewall is used.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\

Value Name: LogSuccessfulConnections

Type: REG_DWORD
Value: 1

If a third-party firewall is used, verify a comparable setting has been implemented.
'

# START_DESCRIBE WN12-FW-000018
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-FW-000018

end
