# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000089 - Explorer Data Execution Prevention must be enabled.'

control 'WN12-CC-000089' do
  impact 0.5
  title 'Explorer Data Execution Prevention must be enabled.'
  desc '
Data Execution Prevention (DEP) provides additional protection by performing  checks on memory to help prevent malicious code from running.  This setting will prevent Data Execution Prevention from being turned off for File Explorer.
'
  tag 'stig','WN12-CC-000089'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000089_chk'
  tag fixid: 'F-WN12-CC-000089_fix'
  tag version: 'WN12-CC-000089'
  tag ruleid: 'WN12-CC-000089_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> File Explorer -> "Turn off Data Execution Prevention for Explorer" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\Explorer\

Value Name: NoDataExecutionPrevention

Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-CC-000089
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000089

end
