# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000002 - The Responder network protocol driver must be disabled.'

control 'WN12-CC-000002' do
  impact 0.5
  title 'The Responder network protocol driver must be disabled.'
  desc '
The Responder network protocol driver allows a computer to be discovered and located on a network.  Disabling this helps protect the system from potentially being discovered and connected to by unauthorized devices.
'
  tag 'stig','WN12-CC-000002'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000002_chk'
  tag fixid: 'F-WN12-CC-000002_fix'
  tag version: 'WN12-CC-000002'
  tag ruleid: 'WN12-CC-000002_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Link-Layer Topology Discovery -> "Turn on Responder (RSPNDR) driver" to "Disabled".
'
  tag checktext: '
If the following registry values do not exist or are not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\LLTD\

Value Name: AllowRspndrOndomain
Value Name: AllowRspndrOnPublicNet
Value Name: EnableRspndr
Value Name: ProhibitRspndrOnPrivateNet

Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-CC-000002
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000002

end
