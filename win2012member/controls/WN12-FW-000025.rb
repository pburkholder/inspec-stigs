# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-FW-000025 - The Windows Firewall local firewall rules must not be merged with Group Policy settings for the Public Profile.'

control 'WN12-FW-000025' do
  impact 0.5
  title 'The Windows Firewall local firewall rules must not be merged with Group Policy settings for the Public Profile.'
  desc '
A firewall provides a line of defense against attack.  To be effective, it must be enabled and properly configured.  Local firewall rules will not be merged with Group Policy settings on a public network to prevent Group Policy settings from being changed.
'
  tag 'stig','WN12-FW-000025'
  tag severity: 'medium'
  tag checkid: 'C-WN12-FW-000025_chk'
  tag fixid: 'F-WN12-FW-000025_fix'
  tag version: 'WN12-FW-000025'
  tag ruleid: 'WN12-FW-000025_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Windows Firewall with Advanced Security -> Windows Firewall with Advanced Security -> Windows Firewall Properties (this link will be in the right pane) -> Public Profile Tab -> Settings (select Customize) -> Rule merging, "Apply local firewall rules:" to "No".

Configure a comparable setting if a third-party firewall is used.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\WindowsFirewall\PublicProfile\

Value Name: AllowLocalPolicyMerge

Type: REG_DWORD
Value: 0

If a third-party firewall is used, verify a comparable setting has been implemented.
'

# START_DESCRIBE WN12-FW-000025
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-FW-000025

end
