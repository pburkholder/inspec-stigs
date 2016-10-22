# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000063 - PKU2U authentication using online identities must be prevented.'

control 'WN12-SO-000063' do
  impact 0.5
  title 'PKU2U authentication using online identities must be prevented.'
  desc '
PKU2U is a peer-to-peer authentication protocol.   This setting prevents online identities from authenticating to domain-joined systems.  Authentication will be centrally managed with Windows user accounts.
'
  tag 'stig','WN12-SO-000063'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000063_chk'
  tag fixid: 'F-WN12-SO-000063_fix'
  tag version: 'WN12-SO-000063'
  tag ruleid: 'WN12-SO-000063_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: Allow PKU2U authentication requests to this computer to use online identities" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \System\CurrentControlSet\Control\LSA\pku2u\

Value Name: AllowOnlineID

Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-SO-000063
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000063

end
