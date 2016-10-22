# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-GE-000017 - System files must be monitored for unauthorized changes.'

control 'WN12-GE-000017' do
  impact 0.5
  title 'System files must be monitored for unauthorized changes.'
  desc '
Monitoring system files for changes against a baseline on a regular basis may help detect the possible introduction of malicious code on a system.
'
  tag 'stig','WN12-GE-000017'
  tag severity: 'medium'
  tag checkid: 'C-WN12-GE-000017_chk'
  tag fixid: 'F-WN12-GE-000017_fix'
  tag version: 'WN12-GE-000017'
  tag ruleid: 'WN12-GE-000017_rule'
  tag fixtext: '
Implement a tool to compare system files (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) on servers against a baseline on a weekly basis.
'
  tag checktext: '
Determine whether the site uses a tool to compare system files (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) on servers against a baseline on a weekly basis.  

A properly configured HBSS Policy Auditor 5.2 or later File Integrity Monitor (FIM) module will meet the requirement for file integrity checking. The Asset module within HBSS does not meet this requirement.
'

# START_DESCRIBE WN12-GE-000017
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-GE-000017

end
