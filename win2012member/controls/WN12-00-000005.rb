# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-00-000005 - Users with Administrative privileges must have separate accounts for administrative duties and normal operational tasks.'

control 'WN12-00-000005' do
  impact 1.0
  title 'Users with Administrative privileges must have separate accounts for administrative duties and normal operational tasks.'
  desc '
Using a privileged account to perform routine functions makes the computer vulnerable to malicious software inadvertently introduced during a session that has been granted full privileges.
'
  tag 'stig','WN12-00-000005'
  tag severity: 'high'
  tag checkid: 'C-WN12-00-000005_chk'
  tag fixid: 'F-WN12-00-000005_fix'
  tag version: 'WN12-00-000005'
  tag ruleid: 'WN12-00-000005_rule'
  tag fixtext: '
Ensure each user with administrative privileges has a separate account for user duties and one for privileged duties.
'
  tag checktext: '
Verify each user with administrative privileges has been assigned a unique administrative account separate from their standard user account. 

The IAO must maintain a list of all users belonging to the Administrators group. 

If users with administrative privileges do not have separate accounts for administrative functions and standard user functions, this is a finding.
'

# START_DESCRIBE WN12-00-000005
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-00-000005

end
