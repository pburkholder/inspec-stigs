# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000088 - Optional Subsystems must not be permitted to operate on the system.'

control 'WN12-SO-000088' do
  impact 0.1
  title 'Optional Subsystems must not be permitted to operate on the system.'
  desc '
The POSIX subsystem is an Institute of Electrical and Electronic Engineers (IEEE) standard that defines a set of operating system services.  The POSIX Subsystem is required if the server supports applications that use that subsystem.  The subsystem introduces a security risk relating to processes that can potentially persist across logins.  That is, if a user starts a process and then logs out, there is a potential that the next user who logs in to the system could access the previous users process.  This is dangerous because the process started by the first user may retain that users system privileges, and anything the second user does with that process will be performed with the privileges of the first user.
'
  tag 'stig','WN12-SO-000088'
  tag severity: 'low'
  tag checkid: 'C-WN12-SO-000088_chk'
  tag fixid: 'F-WN12-SO-000088_fix'
  tag version: 'WN12-SO-000088'
  tag ruleid: 'WN12-SO-000088_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "System settings: Optional subsystems" to "Blank" (Configured with no entries).
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Session Manager\Subsystems\

Value Name: Optional

Value Type: REG_MULTI_SZ
Value: (Blank)
'

# START_DESCRIBE WN12-SO-000088
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000088

end
