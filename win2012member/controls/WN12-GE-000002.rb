# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-GE-000002 - An approved DoD antivirus program must be installed and used.'

control 'WN12-GE-000002' do
  impact 1.0
  title 'An approved DoD antivirus program must be installed and used.'
  desc '
Virus scan programs are a primary line of defense against the introduction of viruses and malicious code that can destroy data and even render a computer inoperable.  Utilizing a virus scan program provides the ability to detect malicious code before extensive damage occurs.
'
  tag 'stig','WN12-GE-000002'
  tag severity: 'high'
  tag checkid: 'C-WN12-GE-000002_chk'
  tag fixid: 'F-WN12-GE-000002_fix'
  tag version: 'WN12-GE-000002'
  tag ruleid: 'WN12-GE-000002_rule'
  tag fixtext: '
Install DoD-approved virus scanning software.
'
  tag checktext: '
If one of the following products is not installed and supported at an appropriate maintenance level, this is a finding:

McAfee VirusScan Enterprise Version 8.8 Patch 3 or later
Symantec Endpoint Protection (SEP) 12.1 Release Update 2 or later

Severity Override:  If another recognized antivirus product is installed, this would still be a finding; however, the severity code may be reduced to a CAT III.
'

# START_DESCRIBE WN12-GE-000002
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-GE-000002

end
