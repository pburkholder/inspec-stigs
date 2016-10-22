# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-00-000001 - Server systems must be located in a controlled access area.'

control 'WN12-00-000001' do
  impact 0.5
  title 'Server systems must be located in a controlled access area.'
  desc '
Inadequate physical protection can undermine all other security precautions utilized to protect the system.  This can jeopardize the confidentiality, availability, and integrity of the system.  Physical security is the first line of protection of any system.
'
  tag 'stig','WN12-00-000001'
  tag severity: 'medium'
  tag checkid: 'C-WN12-00-000001_chk'
  tag fixid: 'F-WN12-00-000001_fix'
  tag version: 'WN12-00-000001'
  tag ruleid: 'WN12-00-000001_rule'
  tag fixtext: '
Ensure servers are located in secure, access-controlled areas.
'
  tag checktext: '
Verify servers are located in controlled access areas that are accessible only to authorized personnel.  If systems are not adequately protected, this is a finding.
'

# START_DESCRIBE WN12-00-000001
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-00-000001

end
