# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000068 - The system must be configured to the required LDAP client signing level.'

control 'WN12-SO-000068' do
  impact 0.5
  title 'The system must be configured to the required LDAP client signing level.'
  desc '
This setting controls the signing requirements for LDAP clients.  This setting must be set to Negotiate signing or Require signing, depending on the environment and type of LDAP server in use.
'
  tag 'stig','WN12-SO-000068'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000068_chk'
  tag fixid: 'F-WN12-SO-000068_fix'
  tag version: 'WN12-SO-000068'
  tag ruleid: 'WN12-SO-000068_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: LDAP client signing requirements" to "Negotiate signing" at a minimum.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\LDAP\

Value Name: LDAPClientIntegrity

Value Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-SO-000068
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000068

end
