# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000030 - Unencrypted passwords must not be sent to a third-party SMB server.'

control 'WN12-SO-000030' do
  impact 0.5
  title 'Unencrypted passwords must not be sent to a third-party SMB server.'
  desc '
Some non-Microsoft SMB servers only support unencrypted (plain text) password authentication.  Sending plain text passwords across the network, when authenticating to an SMB server, reduces the overall security of the environment.  Check with the vendor of the SMB server to see if there is a way to support encrypted password authentication.
'
  tag 'stig','WN12-SO-000030'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000030_chk'
  tag fixid: 'F-WN12-SO-000030_fix'
  tag version: 'WN12-SO-000030'
  tag ruleid: 'WN12-SO-000030_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Microsoft network client: Send unencrypted password to connect to third-party SMB servers" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\LanmanWorkstation\Parameters\

Value Name: EnablePlainTextPassword

Value Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-SO-000030
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000030

end
