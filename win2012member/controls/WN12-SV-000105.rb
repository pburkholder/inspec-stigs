# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SV-000105 - The Telnet service must be disabled if installed.'

control 'WN12-SV-000105' do
  impact 0.5
  title 'The Telnet service must be disabled if installed.'
  desc '
Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption.
'
  tag 'stig','WN12-SV-000105'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SV-000105_chk'
  tag fixid: 'F-WN12-SV-000105_fix'
  tag version: 'WN12-SV-000105'
  tag ruleid: 'WN12-SV-000105_rule'
  tag fixtext: '
Remove or disable the Telnet (tlntsvr) service.
'
  tag checktext: '
Verify the Telnet (tlntsvr) service is not installed or is disabled. 

Run "Services.msc".

If the following is installed and not disabled, this is a finding:

Telnet (tlntsvr)
'

# START_DESCRIBE WN12-SV-000105
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SV-000105

end
