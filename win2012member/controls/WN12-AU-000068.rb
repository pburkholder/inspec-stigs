# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-AU-000068 - The system must be configured to audit Object Access - File System failures.'

control 'WN12-AU-000068' do
  impact 0.5
  title 'The system must be configured to audit Object Access - File System failures.'
  desc '
Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

File System auditing under Object Access is used to enable the recording of events related to the access and changing of files and directories.  Auditing must also be enabled on the specific file system objects to be audited.
'
  tag 'stig','WN12-AU-000068'
  tag severity: 'medium'
  tag checkid: 'C-WN12-AU-000068_chk'
  tag fixid: 'F-WN12-AU-000068_fix'
  tag version: 'WN12-AU-000068'
  tag ruleid: 'WN12-AU-000068_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Object Access -> "Audit File System" with "Failure" selected.
'
  tag checktext: '
Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (V-14230) for the detailed auditing subcategories to be effective. 

Use the AuditPol tool to review the current Audit Policy configuration:
-Open a Command Prompt with elevated privileges ("Run as Administrator").
-Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following.  If the system does not audit the following, this is a finding.

Object Access -> File System - Failure
'

# START_DESCRIBE WN12-AU-000068
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-AU-000068

end
