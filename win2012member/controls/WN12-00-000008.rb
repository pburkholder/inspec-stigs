# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-00-000008 - Policy must require that administrative user accounts not be used with applications that access the Internet, such as web browsers, or with potential Internet sources, such as email.'

control 'WN12-00-000008' do
  impact 1.0
  title 'Policy must require that administrative user accounts not be used with applications that access the Internet, such as web browsers, or with potential Internet sources, such as email.'
  desc '
Using applications that access the Internet or have potential Internet sources using administrative privileges exposes a system to compromise.  If a flaw in an application is exploited while running as a privileged user, the entire system could be compromised.  Web browsers and email are common attack vectors for introducing malicious code and must not be run with an administrative user account.

Since administrative user accounts may generally change or work around technical restrictions for running a web browser or other applications, it is essential that policy requires administrative users to not access the Internet or use applications, such as email.

The policy should define specific exceptions for local service administration.  These exceptions may include HTTP(S)-based tools that are used for the administration of the local system, services, or attached devices.
'
  tag 'stig','WN12-00-000008'
  tag severity: 'high'
  tag checkid: 'C-WN12-00-000008_chk'
  tag fixid: 'F-WN12-00-000008_fix'
  tag version: 'WN12-00-000008'
  tag ruleid: 'WN12-00-000008_rule'
  tag fixtext: '
Establish a site policy to prohibit the use of applications that access the Internet, such as web browsers, or with potential Internet sources, such as email, by administrative user accounts.  Ensure the policy is enforced.
'
  tag checktext: '
Determine whether site policy prohibits the use of applications that access the Internet, such as web browsers, or with potential Internet sources, such as email, by administrative user accounts, except as necessary for local service administration.  If it does not, this is a finding.
'

# START_DESCRIBE WN12-00-000008
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-00-000008

end
