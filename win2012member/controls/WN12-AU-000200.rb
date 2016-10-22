# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-AU-000200 - Audit data must be reviewed on a regular basis.'

control 'WN12-AU-000200' do
  impact 0.5
  title 'Audit data must be reviewed on a regular basis.'
  desc '
To be of value, audit logs from critical systems must be reviewed on a regular basis.  Critical systems should be reviewed on a daily basis to identify security breaches and potential weaknesses in the security structure.  This can be done with the use of monitoring software or other utilities for this purpose.
'
  tag 'stig','WN12-AU-000200'
  tag severity: 'medium'
  tag checkid: 'C-WN12-AU-000200_chk'
  tag fixid: 'F-WN12-AU-000200_fix'
  tag version: 'WN12-AU-000200'
  tag ruleid: 'WN12-AU-000200_rule'
  tag fixtext: '
Establish a site policy that defines a schedule for the review of audit logs.  Review audit logs as scheduled.
'
  tag checktext: '
Determine whether the organization has a policy that requires the review of audit logs on a predetermined schedule and that the policy has been implemented.  If audit logs are not reviewed on a regular basis, this is a finding.
'

# START_DESCRIBE WN12-AU-000200
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-AU-000200

end
