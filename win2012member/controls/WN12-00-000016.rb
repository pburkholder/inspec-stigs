# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-00-000016 - Backups of system-level information must be protected.'

control 'WN12-00-000016' do
  impact 0.1
  title 'Backups of system-level information must be protected.'
  desc '
A system backup will usually include sensitive information such as user accounts that could be used in an attack.  As a valuable system resource, the system backup must be protected and stored in a physically secure location.
'
  tag 'stig','WN12-00-000016'
  tag severity: 'low'
  tag checkid: 'C-WN12-00-000016_chk'
  tag fixid: 'F-WN12-00-000016_fix'
  tag version: 'WN12-00-000016'
  tag ruleid: 'WN12-00-000016_rule'
  tag fixtext: '
Ensure system-level information backups are stored in a secure location and protected from destruction.
'
  tag checktext: '
Determine if system-level information backups are protected from destruction and stored in a physically secure location.  If they are not, this is a finding.
'

# START_DESCRIBE WN12-00-000016
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-00-000016

end
