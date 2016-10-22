# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-GE-000100 - The Enhanced Mitigation Experience Toolkit (EMET) must be installed on the system.'

control 'WN12-GE-000100' do
  impact 0.5
  title 'The Enhanced Mitigation Experience Toolkit (EMET) must be installed on the system.'
  desc '
Attackers are constantly looking for vulnerabilities in systems and applications. The Enhanced Mitigation Experience Toolkit can enable several mechanisms, such as Data Execution Prevention (DEP), Address Space Layout Randomization (ASLR), and Structured Exception Handler Overwrite Protection (SEHOP) on the system and applications, adding additional levels of protection.
'
  tag 'stig','WN12-GE-000100'
  tag severity: 'medium'
  tag checkid: 'C-WN12-GE-000100_chk'
  tag fixid: 'F-WN12-GE-000100_fix'
  tag version: 'WN12-GE-000100'
  tag ruleid: 'WN12-GE-000100_rule'
  tag fixtext: '
Install EMET V4.0 or later on the system. EMET is available for download from Microsoft.
'
  tag checktext: '
Verify EMET V4.0 or later is installed on the system.

If EMET is not installed, or at the minimum required version, this is a finding.
'

# START_DESCRIBE WN12-GE-000100
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-GE-000100

end
