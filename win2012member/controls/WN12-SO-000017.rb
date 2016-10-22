# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000017 - The system must be configured to require a strong session key.'

control 'WN12-SO-000017' do
  impact 0.5
  title 'The system must be configured to require a strong session key.'
  desc '
A computer connecting to a domain controller will establish a secure channel.  Requiring strong session keys enforces 128-bit encryption between systems.
'
  tag 'stig','WN12-SO-000017'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000017_chk'
  tag fixid: 'F-WN12-SO-000017_fix'
  tag version: 'WN12-SO-000017'
  tag ruleid: 'WN12-SO-000017_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Domain member: Require strong (Windows 2000 or Later) session key" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\Netlogon\Parameters\

Value Name: RequireStrongKey

Value Type: REG_DWORD
Value: 1
 
This setting may prevent a system from being joined to a domain if not configured consistently between systems.
'

# START_DESCRIBE WN12-SO-000017
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000017

end
