# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-AU-000201 - Audit data must be retained for at least one year.'

control 'WN12-AU-000201' do
  impact 0.5
  title 'Audit data must be retained for at least one year.'
  desc '
Audit records are essential for investigating system activity after the fact.  Retention periods for audit data are determined based on the sensitivity of the data handled by the system.
'
  tag 'stig','WN12-AU-000201'
  tag severity: 'medium'
  tag checkid: 'C-WN12-AU-000201_chk'
  tag fixid: 'F-WN12-AU-000201_fix'
  tag version: 'WN12-AU-000201'
  tag ruleid: 'WN12-AU-000201_rule'
  tag fixtext: '
Establish a policy that will ensure the retention of audit data for at least one year.  Ensure the audit retention policy is implemented.
'
  tag checktext: '
Determine whether the organization has a policy that requires audit data to be retained for at least one year.  If the data is not retained for this period, this is a finding.
'

# START_DESCRIBE WN12-AU-000201
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-AU-000201

end
