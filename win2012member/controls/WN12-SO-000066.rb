# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000066 - The system must be configured to force users to log off when their allowed logon hours expire.'

control 'WN12-SO-000066' do
  impact 0.5
  title 'The system must be configured to force users to log off when their allowed logon hours expire.'
  desc '
Limiting logon hours can help protect data by only allowing access during specified times.  This setting controls whether or not users are forced to log off when their allowed logon hours expire.  If logon hours are set for users, this must be enforced.
'
  tag 'stig','WN12-SO-000066'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000066_chk'
  tag fixid: 'F-WN12-SO-000066_fix'
  tag version: 'WN12-SO-000066'
  tag ruleid: 'WN12-SO-000066_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: Force logoff when logon hours expire" to "Enabled".
'
  tag checktext: '
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options.

If the value for "Network security: Force logoff when logon hours expire" is not set to "Enabled", this is a finding.
'

# START_DESCRIBE WN12-SO-000066
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000066

end
