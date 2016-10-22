# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000031 - The amount of idle time required before suspending a session must be properly set.'

control 'WN12-SO-000031' do
  impact 0.1
  title 'The amount of idle time required before suspending a session must be properly set.'
  desc '
Open sessions can increase the avenues of attack on a system.  This setting is used to control when a computer disconnects an inactive SMB session.  If client activity resumes, the session is automatically reestablished.  This protects critical and sensitive network data from exposure to unauthorized personnel with physical access to the computer.
'
  tag 'stig','WN12-SO-000031'
  tag severity: 'low'
  tag checkid: 'C-WN12-SO-000031_chk'
  tag fixid: 'F-WN12-SO-000031_fix'
  tag version: 'WN12-SO-000031'
  tag ruleid: 'WN12-SO-000031_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Microsoft network server: Amount of idle time required before suspending a session" to "15" minutes or less.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\LanManServer\Parameters\

Value Name: AutoDisconnect

Value Type: REG_DWORD
Value: 15 (or less)
'

# START_DESCRIBE WN12-SO-000031
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000031

end
