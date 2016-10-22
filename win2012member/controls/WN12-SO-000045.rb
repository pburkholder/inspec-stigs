# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000045 - The system must be configured to use Safe DLL Search Mode.'

control 'WN12-SO-000045' do
  impact 0.5
  title 'The system must be configured to use Safe DLL Search Mode.'
  desc '
The default search behavior, when an application calls a function in a Dynamic Link Library (DLL), is to search the current directory, followed by the directories contained in the system\'s path environment variable.  An unauthorized DLL, inserted into an application\'s working directory, could allow malicious code to be run on the system.  Setting this policy value forces the system to search the %Systemroot% for the DLL before searching the current directory or the rest of the path.
'
  tag 'stig','WN12-SO-000045'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000045_chk'
  tag fixid: 'F-WN12-SO-000045_fix'
  tag version: 'WN12-SO-000045'
  tag ruleid: 'WN12-SO-000045_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)" to "Enabled".

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system\'s policy tools.)
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Session Manager\

Value Name: SafeDllSearchMode

Value Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-SO-000045
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000045

end
