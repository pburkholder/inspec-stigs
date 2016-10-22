# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-00-000004 - Users with administrative privilege must be documented.'

control 'WN12-00-000004' do
  impact 0.5
  title 'Users with administrative privilege must be documented.'
  desc '
Administrative accounts may perform any action on a system.  Users with administrative accounts must be documented to ensure those with this level of access are clearly identified.
'
  tag 'stig','WN12-00-000004'
  tag severity: 'medium'
  tag checkid: 'C-WN12-00-000004_chk'
  tag fixid: 'F-WN12-00-000004_fix'
  tag version: 'WN12-00-000004'
  tag ruleid: 'WN12-00-000004_rule'
  tag fixtext: '
Create the necessary documentation that identifies the members of the Administrators group.
'
  tag checktext: '
Review the necessary documentation that identifies the members of the Administrators group.  If a list of all users belonging to the Administrators group is not maintained with the IAO, this is a finding.
'

# START_DESCRIBE WN12-00-000004
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-00-000004

end
