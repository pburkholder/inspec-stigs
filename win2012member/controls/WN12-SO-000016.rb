# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000016 - The maximum age for machine account passwords must be set to requirements.'

control 'WN12-SO-000016' do
  impact 0.1
  title 'The maximum age for machine account passwords must be set to requirements.'
  desc '
Computer account passwords are changed automatically on a regular basis.  This setting controls the maximum password age that a machine account may have.  This setting must be set to no more than 30 days, ensuring the machine changes its password monthly.
'
  tag 'stig','WN12-SO-000016'
  tag severity: 'low'
  tag checkid: 'C-WN12-SO-000016_chk'
  tag fixid: 'F-WN12-SO-000016_fix'
  tag version: 'WN12-SO-000016'
  tag ruleid: 'WN12-SO-000016_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Domain member: Maximum machine account password age" to "30" or less (excluding "0" which is unacceptable).
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\Netlogon\Parameters\

Value Name: MaximumPasswordAge

Value Type: REG_DWORD
Value: 30 (or less, but not 0)
'

# START_DESCRIBE WN12-SO-000016
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000016

end
