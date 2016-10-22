# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SV-000104 - The Simple TCP/IP Services service must be disabled if installed.'

control 'WN12-SV-000104' do
  impact 0.5
  title 'The Simple TCP/IP Services service must be disabled if installed.'
  desc '
Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption.
'
  tag 'stig','WN12-SV-000104'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SV-000104_chk'
  tag fixid: 'F-WN12-SV-000104_fix'
  tag version: 'WN12-SV-000104'
  tag ruleid: 'WN12-SV-000104_rule'
  tag fixtext: '
Remove or disable the Simple TCP/IP Services (simptcp) service.
'
  tag checktext: '
Verify the Simple TCP/IP (simptcp) service is not installed or is disabled. 

Run "Services.msc".

If the following is installed and not disabled, this is a finding:

Simple TCP/IP Services (simptcp)
'

# START_DESCRIBE WN12-SV-000104
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SV-000104

end
