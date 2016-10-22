# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-AU-000102 - The system must be configured to audit Privilege Use - Sensitive Privilege Use failures.'

control 'WN12-AU-000102' do
  impact 0.5
  title 'The system must be configured to audit Privilege Use - Sensitive Privilege Use failures.'
  desc '
Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Sensitive Privilege Use records events related to use of sensitive privileges, such as "Act as part of the operating system" or "Debug programs".
'
  tag 'stig','WN12-AU-000102'
  tag severity: 'medium'
  tag checkid: 'C-WN12-AU-000102_chk'
  tag fixid: 'F-WN12-AU-000102_fix'
  tag version: 'WN12-AU-000102'
  tag ruleid: 'WN12-AU-000102_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Privilege Use -> "Audit Sensitive Privilege Use" with "Failure" selected.
'
  tag checktext: '
Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (V-14230) for the detailed auditing subcategories to be effective. 

Use the AuditPol tool to review the current Audit Policy configuration:
-Open a Command Prompt with elevated privileges ("Run as Administrator").
-Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following.  If the system does not audit the following, this is a finding.

Privilege Use -> Sensitive Privilege Use - Failure
'

# START_DESCRIBE WN12-AU-000102
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-AU-000102

end
