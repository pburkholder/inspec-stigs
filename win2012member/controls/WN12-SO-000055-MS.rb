# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000055-MS - Named pipes that can be accessed anonymously must be configured to contain no values.'

control 'WN12-SO-000055-MS' do
  impact 1.0
  title 'Named pipes that can be accessed anonymously must be configured to contain no values.'
  desc '
Named pipes that can be accessed anonymously provide the potential for gaining unauthorized system access.  Pipes are internal system communications processes.  They are identified internally by ID numbers that vary between systems.  To make access to these processes easier, these pipes are given names that do not vary between systems.  This setting controls which of these pipes anonymous users may access.
'
  tag 'stig','WN12-SO-000055-MS'
  tag severity: 'high'
  tag checkid: 'C-WN12-SO-000055-MS_chk'
  tag fixid: 'F-WN12-SO-000055-MS_fix'
  tag version: 'WN12-SO-000055-MS'
  tag ruleid: 'WN12-SO-000055-MS_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Named pipes that can be accessed anonymously" to be defined but containing no entries (blank).
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\LanManServer\Parameters\

Value Name: NullSessionPipes

Value Type: REG_MULTI_SZ
Value: (blank)

Legitimate applications may add entries to this registry value. If an application requires these entries to function properly and is documented with the IAO, this would not be a finding.  Documentation must contain supporting information from the vendor\'s instructions.
'

# START_DESCRIBE WN12-SO-000055-MS
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000055-MS

end
