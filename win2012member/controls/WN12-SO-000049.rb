# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000049 - The system must generate an audit event when the audit log reaches a percentage of full threshold.'

control 'WN12-SO-000049' do
  impact 0.1
  title 'The system must generate an audit event when the audit log reaches a percentage of full threshold.'
  desc '
When the audit log reaches a given percent full, an audit event is written to the security log.  It is recorded as a successful audit event under the category of System.  This option may be especially useful if the audit logs are set to be cleared manually.
'
  tag 'stig','WN12-SO-000049'
  tag severity: 'low'
  tag checkid: 'C-WN12-SO-000049_chk'
  tag fixid: 'F-WN12-SO-000049_fix'
  tag version: 'WN12-SO-000049'
  tag ruleid: 'WN12-SO-000049_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning" to "90" or less.

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system\'s policy tools.)
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\Eventlog\Security\

Value Name: WarningLevel

Value Type: REG_DWORD
Value: 90 (or less)

If the system is configured to write to an audit server, or is configured to automatically archive full logs, this is not a finding.
'

# START_DESCRIBE WN12-SO-000049
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000049

end
