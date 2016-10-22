# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-00-000013 - Security configuration tools or equivalent processes must be used to configure and maintain platforms for security compliance.'

control 'WN12-00-000013' do
  impact 0.1
  title 'Security configuration tools or equivalent processes must be used to configure and maintain platforms for security compliance.'
  desc '
Security configuration tools such as Group Policies and Security Templates allow system administrators to consolidate security-related system settings into a single configuration file.  These settings can then be applied consistently to any number of Windows machines.
'
  tag 'stig','WN12-00-000013'
  tag severity: 'low'
  tag checkid: 'C-WN12-00-000013_chk'
  tag fixid: 'F-WN12-00-000013_fix'
  tag version: 'WN12-00-000013'
  tag ruleid: 'WN12-00-000013_rule'
  tag fixtext: '
Implement a process using security configuration tools or the equivalent to configure Windows systems to meet security requirements.
'
  tag checktext: '
Verify security configuration tools or equivalent processes are being used to configure Windows systems to meet security requirements.  Security configuration tools that are integrated into Windows, such as Group Policies and Security Templates, may be used to configure platforms for security compliance.

If an alternate method is used to configure a system (e.g., manually using the DISA Windows Security STIGs, etc.) and the same configured result is achieved, this is acceptable.
'

# START_DESCRIBE WN12-00-000013
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-00-000013

end
