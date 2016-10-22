# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000008 - Auditing of Backup and Restore Privileges must be turned off.'

control 'WN12-SO-000008' do
  impact 0.5
  title 'Auditing of Backup and Restore Privileges must be turned off.'
  desc '
Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.  
This setting prevents the system from generating audit events for every file backed up or restored, which could fill the security log in Windows, making it difficult to identify actual issues.
'
  tag 'stig','WN12-SO-000008'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000008_chk'
  tag fixid: 'F-WN12-SO-000008_fix'
  tag version: 'WN12-SO-000008'
  tag ruleid: 'WN12-SO-000008_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Audit: Audit the use of Backup and Restore privilege" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Lsa

Value Name: FullPrivilegeAuditing

Value Type: REG_BINARY
Value: 0
'

# START_DESCRIBE WN12-SO-000008
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000008

end
