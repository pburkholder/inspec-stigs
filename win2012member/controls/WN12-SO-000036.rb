# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000036 - Automatic logons must be disabled.'

control 'WN12-SO-000036' do
  impact 0.5
  title 'Automatic logons must be disabled.'
  desc '
Allowing a system to automatically log on when the machine is booted could give access to any unauthorized individual who restarts the computer.  Automatic logon with administrator privileges would give full access to an unauthorized individual.
'
  tag 'stig','WN12-SO-000036'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000036_chk'
  tag fixid: 'F-WN12-SO-000036_fix'
  tag version: 'WN12-SO-000036'
  tag ruleid: 'WN12-SO-000036_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)" to "Disabled".

Ensure no passwords are stored in the "DefaultPassword" registry value noted below:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Microsoft\Windows NT\CurrentVersion\Winlogon\

Value Name: DefaultPassword

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system\'s policy tools.)
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Microsoft\Windows NT\CurrentVersion\Winlogon\

Value Name: AutoAdminLogon

Type: REG_SZ
Value: 0

Severity Override:  If the "DefaultName" or "DefaultDomainName" in the same registry path contain an administrator account name and the "DefaultPassword" contains a value, this is a CAT I finding.
'

# START_DESCRIBE WN12-SO-000036
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000036

end
