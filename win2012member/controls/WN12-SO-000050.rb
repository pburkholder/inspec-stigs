# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000050 - Anonymous SID/Name translation must not be allowed.'

control 'WN12-SO-000050' do
  impact 1.0
  title 'Anonymous SID/Name translation must not be allowed.'
  desc '
Allowing anonymous SID/Name translation can provide sensitive information for accessing a system.  Only authorized users must be able to perform such translations.
'
  tag 'stig','WN12-SO-000050'
  tag severity: 'high'
  tag checkid: 'C-WN12-SO-000050_chk'
  tag fixid: 'F-WN12-SO-000050_fix'
  tag version: 'WN12-SO-000050'
  tag ruleid: 'WN12-SO-000050_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Allow anonymous SID/Name translation" to "Disabled".
'
  tag checktext: '
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options.

If the value for "Network access: Allow anonymous SID/Name translation" is not set to "Disabled", this is a finding.
'

# START_DESCRIBE WN12-SO-000050
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000050

end
