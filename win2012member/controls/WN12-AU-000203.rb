# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-AU-000203 - Audit records must be backed up on an organization defined frequency onto a different system or media than the system being audited.'

control 'WN12-AU-000203' do
  impact 0.5
  title 'Audit records must be backed up on an organization defined frequency onto a different system or media than the system being audited.'
  desc '
Protection of log data includes assuring the log data is not accidentally lost or deleted.  Backing up audit records to a different system or onto separate media than the system being audited on an organization defined frequency helps to assure in the event of a catastrophic system failure, the audit records will be retained.
'
  tag 'stig','WN12-AU-000203'
  tag severity: 'medium'
  tag checkid: 'C-WN12-AU-000203_chk'
  tag fixid: 'F-WN12-AU-000203_fix'
  tag version: 'WN12-AU-000203'
  tag ruleid: 'WN12-AU-000203_rule'
  tag fixtext: '
Establish and implement a process for backing up log data on an organization defined frequency to another system or media other than the system being audited.
'
  tag checktext: '
Determine if a process to backup log data on an organization defined frequency to a different system or media than the system being audited has been implemented.  If it has not, this is a finding.
'

# START_DESCRIBE WN12-AU-000203
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-AU-000203

end
