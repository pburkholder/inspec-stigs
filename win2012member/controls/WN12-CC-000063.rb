# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000063 - Client computers must be required to authenticate for RPC communication.'

control 'WN12-CC-000063' do
  impact 0.5
  title 'Client computers must be required to authenticate for RPC communication.'
  desc '
Configuring RPC to require authentication to the RPC Endpoint Mapper will force clients to provide authentication before RPC communication is established.
'
  tag 'stig','WN12-CC-000063'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000063_chk'
  tag fixid: 'F-WN12-CC-000063_fix'
  tag version: 'WN12-CC-000063'
  tag ruleid: 'WN12-CC-000063_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Remote Procedure Call -> "Enable RPC Endpoint Mapper Client Authentication" to "Enabled.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Rpc\

Value Name: EnableAuthEpResolution

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000063
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000063

end
