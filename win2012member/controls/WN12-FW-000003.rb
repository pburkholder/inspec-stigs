# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-FW-000003 - The Windows Firewall must allow outbound connections, unless a rule explicitly blocks the connection for the Domain Profile.'

control 'WN12-FW-000003' do
  impact 0.5
  title 'The Windows Firewall must allow outbound connections, unless a rule explicitly blocks the connection for the Domain Profile.'
  desc '
A firewall provides a line of defense against attack.  To be effective, it must be enabled and properly configured.  Outbound connections are allowed in the domain, unless a rule explicitly blocks the connection.  This allows normal outbound communication, which could be restricted as necessary with additional rules.
'
  tag 'stig','WN12-FW-000003'
  tag severity: 'medium'
  tag checkid: 'C-WN12-FW-000003_chk'
  tag fixid: 'F-WN12-FW-000003_fix'
  tag version: 'WN12-FW-000003'
  tag ruleid: 'WN12-FW-000003_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Windows Firewall with Advanced Security -> Windows Firewall with Advanced Security -> Windows Firewall Properties (this link will be in the right pane) -> Domain Profile Tab -> State, "Outbound connections" to "Allow (default)".

Configure a comparable setting if a third-party firewall is used.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\WindowsFirewall\DomainProfile\

Value Name: DefaultOutboundAction

Type: REG_DWORD
Value: 0

If the Windows Firewall is used and the system is not a member of a domain, the Domain Profile requirements can be marked NA.

If a third-party firewall is used, verify a comparable setting has been implemented.
'

# START_DESCRIBE WN12-FW-000003
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-FW-000003

end
