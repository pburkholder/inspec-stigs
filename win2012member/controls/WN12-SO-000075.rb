# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000075 - The system must be configured to require case insensitivity for non-Windows subsystems.'

control 'WN12-SO-000075' do
  impact 0.5
  title 'The system must be configured to require case insensitivity for non-Windows subsystems.'
  desc '
This setting controls the behavior of non-Windows subsystems when dealing with the case of arguments or commands.  Case sensitivity could lead to the access of files or commands that must be restricted.  To prevent this from happening, case insensitivity restrictions must be required.
'
  tag 'stig','WN12-SO-000075'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000075_chk'
  tag fixid: 'F-WN12-SO-000075_fix'
  tag version: 'WN12-SO-000075'
  tag ruleid: 'WN12-SO-000075_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "System objects: Require case insensitivity for non-Windows subsystems" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Session Manager\Kernel\

Value Name: ObCaseInsensitive

Value Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-SO-000075
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000075

end
