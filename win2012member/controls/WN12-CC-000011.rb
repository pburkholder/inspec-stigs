# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000011 - IP stateless autoconfiguration limits state must be enabled.'

control 'WN12-CC-000011' do
  impact 0.1
  title 'IP stateless autoconfiguration limits state must be enabled.'
  desc '
IP stateless autoconfiguration could configure routes that circumvent preferred routes if not limited.
'
  tag 'stig','WN12-CC-000011'
  tag severity: 'low'
  tag checkid: 'C-WN12-CC-000011_chk'
  tag fixid: 'F-WN12-CC-000011_fix'
  tag version: 'WN12-CC-000011'
  tag ruleid: 'WN12-CC-000011_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> TCPIP Settings -> Parameters -> "Set IP Stateless Autoconfiguration Limits State" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \System\CurrentControlSet\Services\Tcpip\Parameters\

Value Name: EnableIPAutoConfigurationLimits

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000011
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000011

end
