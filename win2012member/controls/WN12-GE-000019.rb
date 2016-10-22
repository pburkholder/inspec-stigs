# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-GE-000019 - The HBSS McAfee Agent must be installed.'

control 'WN12-GE-000019' do
  impact 0.5
  title 'The HBSS McAfee Agent must be installed.'
  desc '

'
  tag 'stig','WN12-GE-000019'
  tag severity: 'medium'
  tag checkid: 'C-WN12-GE-000019_chk'
  tag fixid: 'F-WN12-GE-000019_fix'
  tag version: 'WN12-GE-000019'
  tag ruleid: 'WN12-GE-000019_rule'
  tag fixtext: '
Deploy the McAfee Agent as detailed in accordance with the DoD HBSS STIG.
'
  tag checktext: '
Search for the file FrameworkService.exe (by default in the \Program Files\McAfee\Common Framework\ directory) and check that the version is 4 or above.

Also verify that the Service "McAfee Framework Service" is running.

If either of these conditions does not exist, this is a finding.
'

# START_DESCRIBE WN12-GE-000019
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-GE-000019

end
