# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-00-000007 - Passwords for the built-in Administrator account must be changed regularly.'

control 'WN12-00-000007' do
  impact 0.5
  title 'Passwords for the built-in Administrator account must be changed regularly.'
  desc '
The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the password.   Passwords for the built-in Administrator account must be changed at least annually or when any member of the administrative team leaves the organization.
'
  tag 'stig','WN12-00-000007'
  tag severity: 'medium'
  tag checkid: 'C-WN12-00-000007_chk'
  tag fixid: 'F-WN12-00-000007_fix'
  tag version: 'WN12-00-000007'
  tag ruleid: 'WN12-00-000007_rule'
  tag fixtext: '
Define a policy that requires the default administrator passwords to be changed at least annually or when any member of the administrative team leaves the organization.  Ensure the policy is implemented.
'
  tag checktext: '
Determine whether the site has a policy that requires the built-in Administrator account passwords to be changed at least annually or when any member of the administrative team leaves the organization.  If there is no policy, this is a finding.
'

# START_DESCRIBE WN12-00-000007
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-00-000007

end
