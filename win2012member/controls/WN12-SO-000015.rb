# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000015 - The computer account password must not be prevented from being reset.'

control 'WN12-SO-000015' do
  impact 0.1
  title 'The computer account password must not be prevented from being reset.'
  desc '
Computer account passwords are changed automatically on a regular basis.  Disabling automatic password changes can make the system more vulnerable to malicious access.  Frequent password changes can be a significant safeguard for your system.  A new password for the computer account will be generated every 30 days.
'
  tag 'stig','WN12-SO-000015'
  tag severity: 'low'
  tag checkid: 'C-WN12-SO-000015_chk'
  tag fixid: 'F-WN12-SO-000015_fix'
  tag version: 'WN12-SO-000015'
  tag ruleid: 'WN12-SO-000015_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Domain member: Disable machine account password changes" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\Netlogon\Parameters\

Value Name: DisablePasswordChange

Value Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-SO-000015
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000015

end
