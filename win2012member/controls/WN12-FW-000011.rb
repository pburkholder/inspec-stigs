# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-FW-000011 - The Windows Firewall must block unsolicited inbound connections for the Private Profile.'

control 'WN12-FW-000011' do
  impact 1.0
  title 'The Windows Firewall must block unsolicited inbound connections for the Private Profile.'
  desc '
A firewall provides a line of defense against attack.  To be effective, it must be enabled and properly configured.  Unsolicited inbound connections may be malicious attempts to gain access to a system.  Unsolicited inbound connections for which there is no rule allowing the connection will be blocked on a private network.
'
  tag 'stig','WN12-FW-000011'
  tag severity: 'high'
  tag checkid: 'C-WN12-FW-000011_chk'
  tag fixid: 'F-WN12-FW-000011_fix'
  tag version: 'WN12-FW-000011'
  tag ruleid: 'WN12-FW-000011_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Windows Firewall with Advanced Security -> Windows Firewall with Advanced Security -> Windows Firewall Properties (this link will be in the right pane) -> Private Profile Tab -> State, "Inbound connections" to "Block (default)".

Configure a comparable setting if a third-party firewall is used.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\

Value Name: DefaultInboundAction

Type: REG_DWORD
Value: 1

If a third-party firewall is used, verify a comparable setting has been implemented.
'

# START_DESCRIBE WN12-FW-000011
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-FW-000011

end
