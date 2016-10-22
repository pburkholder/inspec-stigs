# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SV-000106 - The Smart Card Removal Policy service must be configured to automatic.'

control 'WN12-SV-000106' do
  impact 0.5
  title 'The Smart Card Removal Policy service must be configured to automatic.'
  desc '
The automatic start of the Smart Card Removal Policy service is required to support the smart card removal behavior requirement.
'
  tag 'stig','WN12-SV-000106'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SV-000106_chk'
  tag fixid: 'F-WN12-SV-000106_fix'
  tag version: 'WN12-SV-000106'
  tag ruleid: 'WN12-SV-000106_rule'
  tag fixtext: '
Configure the Startup Type for the Smart Card Removal Policy service to "Automatic".
'
  tag checktext: '
Verify the Smart Card Removal Policy service is configured to "Automatic". 

Run "Services.msc".

If the Startup Type for Smart Card Removal Policy is not set to Automatic, this is a finding.
'

# START_DESCRIBE WN12-SV-000106
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SV-000106

end
