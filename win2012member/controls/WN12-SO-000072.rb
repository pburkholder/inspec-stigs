# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000072 - The Recovery Console SET command must be disabled.'

control 'WN12-SO-000072' do
  impact 0.1
  title 'The Recovery Console SET command must be disabled.'
  desc '
The Recovery Console SET command allows environment variables to be set in the Recovery Console.  This permits access to all drives and folders  and the copying of files to removable media, which could expose sensitive information.
'
  tag 'stig','WN12-SO-000072'
  tag severity: 'low'
  tag checkid: 'C-WN12-SO-000072_chk'
  tag fixid: 'F-WN12-SO-000072_fix'
  tag version: 'WN12-SO-000072'
  tag ruleid: 'WN12-SO-000072_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Recovery console: Allow floppy copy and access to all drives and folders" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: 
\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\

Value Name: SetCommand

Value Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-SO-000072
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000072

end
