# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-GE-000023 - The system must employ automated mechanisms or must have an application installed that, on an organization defined frequency, determines the state of information system components with regard to flaw remediation.'

control 'WN12-GE-000023' do
  impact 0.5
  title 'The system must employ automated mechanisms or must have an application installed that, on an organization defined frequency, determines the state of information system components with regard to flaw remediation.'
  desc '
Organizations are required to identify information systems containing software affected by recently announced software flaws (and potential vulnerabilities resulting from those flaws) and report this information to designated organizational officials with information security responsibilities (e.g., senior information security officers, information system security managers, information systems security officers).  To support this requirement, an automated process or mechanism is required.
'
  tag 'stig','WN12-GE-000023'
  tag severity: 'medium'
  tag checkid: 'C-WN12-GE-000023_chk'
  tag fixid: 'F-WN12-GE-000023_fix'
  tag version: 'WN12-GE-000023'
  tag ruleid: 'WN12-GE-000023_rule'
  tag fixtext: '
Establish an automated process to scan systems for identified software flaws and vulnerabilities.
'
  tag checktext: '
Verify the organization has an automated process to scan systems for identified software flaws and vulnerabilities.  If it does not, this is a finding.
'

# START_DESCRIBE WN12-GE-000023
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-GE-000023

end
