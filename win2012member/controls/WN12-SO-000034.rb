# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000034 - Users must be forcibly disconnected when their logon hours expire.'

control 'WN12-SO-000034' do
  impact 0.1
  title 'Users must be forcibly disconnected when their logon hours expire.'
  desc '
Users must not be permitted to remain logged on to the network after they have exceeded their permitted logon hours.  In many cases, this indicates that a user forgot to log off before leaving for the day.  However, it may also indicate that a user is attempting unauthorized access at a time when the system may be less closely monitored.  Forcibly disconnecting users when logon hours expire protects critical and sensitive network data from exposure to unauthorized personnel with physical access to the computer.
'
  tag 'stig','WN12-SO-000034'
  tag severity: 'low'
  tag checkid: 'C-WN12-SO-000034_chk'
  tag fixid: 'F-WN12-SO-000034_fix'
  tag version: 'WN12-SO-000034'
  tag ruleid: 'WN12-SO-000034_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Microsoft network server: Disconnect clients when logon hours expire" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\LanManServer\Parameters\

Value Name: EnableForcedLogoff

Value Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-SO-000034
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000034

end
