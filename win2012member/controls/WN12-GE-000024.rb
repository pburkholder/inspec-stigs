# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-GE-000024 - The system must support automated patch management tools to facilitate flaw remediation to organization defined information system components.'

control 'WN12-GE-000024' do
  impact 0.5
  title 'The system must support automated patch management tools to facilitate flaw remediation to organization defined information system components.'
  desc '
The organization (including any contractor to the organization) must promptly install security-relevant software updates (e.g., patches, service packs, hot fixes).  Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed.
'
  tag 'stig','WN12-GE-000024'
  tag severity: 'medium'
  tag checkid: 'C-WN12-GE-000024_chk'
  tag fixid: 'F-WN12-GE-000024_fix'
  tag version: 'WN12-GE-000024'
  tag ruleid: 'WN12-GE-000024_rule'
  tag fixtext: '
Establish a process to automatically install security-related software updates.
'
  tag checktext: '
Verify the organization has an automated process to install security-related software updates.  If it does not, this is a finding.
'

# START_DESCRIBE WN12-GE-000024
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-GE-000024

end
