# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-FW-000014 - The Windows Firewall must block unicast responses to multicast or broadcast messages for the Private Profile.'

control 'WN12-FW-000014' do
  impact 0.5
  title 'The Windows Firewall must block unicast responses to multicast or broadcast messages for the Private Profile.'
  desc '
A firewall provides a line of defense against attack.  To be effective, it must be enabled and properly configured.  Unicast responses to multicast or broadcast messages for a private connection will be blocked.  This helps minimize the risk of an attacker using broadcast or multicast traffic to deliver malicious payloads.
'
  tag 'stig','WN12-FW-000014'
  tag severity: 'medium'
  tag checkid: 'C-WN12-FW-000014_chk'
  tag fixid: 'F-WN12-FW-000014_fix'
  tag version: 'WN12-FW-000014'
  tag ruleid: 'WN12-FW-000014_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Windows Firewall with Advanced Security -> Windows Firewall with Advanced Security -> Windows Firewall Properties (this link will be in the right pane) -> Private Profile Tab -> Settings (select Customize) -> Unicast response, "Allow unicast response" to "No".

Configure a comparable setting if a third-party firewall is used.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\

Value Name: DisableUnicastResponsesToMulticastBroadcast

Type: REG_DWORD
Value: 1

If a third-party firewall is used, verify a comparable setting has been implemented.
'

# START_DESCRIBE WN12-FW-000014
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-FW-000014

end
