# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-00-000018 - Unencrypted remote access to system services must not be permitted.'

control 'WN12-00-000018' do
  impact 1.0
  title 'Unencrypted remote access to system services must not be permitted.'
  desc '
Unencrypted access to system services may permit an intruder to intercept user identification and passwords that are being transmitted in clear text.  This could give an intruder unlimited access to the network.
'
  tag 'stig','WN12-00-000018'
  tag severity: 'high'
  tag checkid: 'C-WN12-00-000018_chk'
  tag fixid: 'F-WN12-00-000018_fix'
  tag version: 'WN12-00-000018'
  tag ruleid: 'WN12-00-000018_rule'
  tag fixtext: '
Establish a site policy to ensure the following are met during remote access:
Userid and password information is encrypted.
User data coming from  or going outside the network firewall is encrypted.  (Encrypting user data within the firewall is also highly recommended).
Administrator data is encrypted.
'
  tag checktext: '
Verify the site has a policy to ensure that encryption of userid and password information is required, and that data is encrypted according to DoD policy.

If the user account used for unencrypted remote access within the enclave (premise router) has administrator privileges, this is a finding.

If userid and password information used for remote access to system services from outside the enclave is not encrypted, this is a finding.
'

# START_DESCRIBE WN12-00-000018
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-00-000018

end
