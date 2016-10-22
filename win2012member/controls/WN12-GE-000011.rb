# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-GE-000011 - Virtual guest operating systems must be registered in a vulnerability and asset management system.'

control 'WN12-GE-000011' do
  impact 0.5
  title 'Virtual guest operating systems must be registered in a vulnerability and asset management system.'
  desc '
Virtual guest operating systems share the same vulnerabilities as operating systems running on dedicated hardware and must be individually assessed for security guidance compliance.  The VMS used may be DISA VMS or a similar vulnerability and asset management system.

'
  tag 'stig','WN12-GE-000011'
  tag severity: 'medium'
  tag checkid: 'C-WN12-GE-000011_chk'
  tag fixid: 'F-WN12-GE-000011_fix'
  tag version: 'WN12-GE-000011'
  tag ruleid: 'WN12-GE-000011_rule'
  tag fixtext: '
Establish site policy to register all virtual guest operating systems as separate assets in a vulnerability and asset management system.
'
  tag checktext: '
Determine if virtual guest operating systems have been registered in a vulnerability and asset management system as separate assets.  If they have not, this is a finding.  If no virtual guest operating systems exist, this is NA.
'

# START_DESCRIBE WN12-GE-000011
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-GE-000011

end
