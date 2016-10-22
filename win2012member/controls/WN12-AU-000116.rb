# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-AU-000116 - Global object access auditing of the registry must be configured to record failures.'

control 'WN12-AU-000116' do
  impact 0.5
  title 'Global object access auditing of the registry must be configured to record failures.'
  desc '
Improper modification of the registry can have a significant impact on the security configuration of a system, as well as potentially rendering a system inoperable.  Failed access attempts may indicate an attack on a system.  Auditing for failed access attempts provides an indicator of such attempts and a method of determining responsible parties.
'
  tag 'stig','WN12-AU-000116'
  tag severity: 'medium'
  tag checkid: 'C-WN12-AU-000116_chk'
  tag fixid: 'F-WN12-AU-000116_fix'
  tag version: 'WN12-AU-000116'
  tag ruleid: 'WN12-AU-000116_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Global Object Access Auditing -> "Registry" with the following:

Principal:  Everyone
Type:  Fail
Permissions:  all categories selected
'
  tag checktext: '
If "Object Access -> Registry" auditing is not properly configured (V-26545), this is a finding.

If "Global Object Access Auditing" of the registry has not been configured to audit all failed access attempts for the "Everyone" group, this is a finding.

Use the AuditPol tool to review the current configuration.
Open a Command Prompt with elevated privileges ("Run as Administrator").
Enter "Auditpol /resourceSACL /type:Key /view". ("Key" in the /type parameter is case sensitive).

The following results should be displayed:

Entry:                   1
Resource Type:  Key
User:                    Everyone
Flags:                   Failure
Condition           <null>
Accesses:
  KEY_ALL_ACCESS
'

# START_DESCRIBE WN12-AU-000116
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-AU-000116

end
