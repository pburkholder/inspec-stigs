# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-00-000017 - System-related documentation must be backed up per organization defined frequency consistent with recovery time and recovery point objectives.'

control 'WN12-00-000017' do
  impact 0.1
  title 'System-related documentation must be backed up per organization defined frequency consistent with recovery time and recovery point objectives.'
  desc '
Operating system backup is a critical step in maintaining data assurance and availability. 

Information system and security-related documentation contains information pertaining to system configuration and security settings. 

Backups shall be consistent with organizational recovery time and recovery point objectives.
'
  tag 'stig','WN12-00-000017'
  tag severity: 'low'
  tag checkid: 'C-WN12-00-000017_chk'
  tag fixid: 'F-WN12-00-000017_fix'
  tag version: 'WN12-00-000017'
  tag ruleid: 'WN12-00-000017_rule'
  tag fixtext: '
Back up system-related documentation to support organizational recovery time and recovery point objectives.
'
  tag checktext: '
Determine whether system-related documentation is backed up to meet organizational recovery time and recovery point objectives.  If system-related documentation is not backed up, this is a finding.
'

# START_DESCRIBE WN12-00-000017
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-00-000017

end
