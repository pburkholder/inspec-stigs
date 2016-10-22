# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-00-000010 - Application account passwords must be at least 15 characters in length.'

control 'WN12-00-000010' do
  impact 0.5
  title 'Application account passwords must be at least 15 characters in length.'
  desc '
Application/service account passwords must be of sufficient length to prevent being easily cracked.  Application/service accounts that are manually managed must have passwords at least 15 characters in length.
'
  tag 'stig','WN12-00-000010'
  tag severity: 'medium'
  tag checkid: 'C-WN12-00-000010_chk'
  tag fixid: 'F-WN12-00-000010_fix'
  tag version: 'WN12-00-000010'
  tag ruleid: 'WN12-00-000010_rule'
  tag fixtext: '
Establish a site policy that defines the requirements for application/service account length.  Create application/service account passwords that are at least 15 characters in length.
'
  tag checktext: '
The site must have a policy to ensure passwords for manually managed application/service accounts are at least 15 characters in length.  If such a policy does not exist or has not been implemented, this is a finding.
'

# START_DESCRIBE WN12-00-000010
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-00-000010

end
