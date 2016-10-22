# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-AC-000008 - The built-in Microsoft password complexity filter must be enabled.'

control 'WN12-AC-000008' do
  impact 0.1
  title 'The built-in Microsoft password complexity filter must be enabled.'
  desc '
The use of complex passwords increases their strength against guessing and brute-force attacks.  This setting configures the system to verify that newly created passwords conform to the Windows password complexity policy.
'
  tag 'stig','WN12-AC-000008'
  tag severity: 'low'
  tag checkid: 'C-WN12-AC-000008_chk'
  tag fixid: 'F-WN12-AC-000008_fix'
  tag version: 'WN12-AC-000008'
  tag ruleid: 'WN12-AC-000008_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy -> "Password must meet complexity requirements" to "Enabled".
'
  tag checktext: '
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy.

If the value for "Password must meet complexity requirements" is not set to "Enabled", this is a finding.

If the site is using a password filter that requires this setting be set to "Disabled" for the filter code to be used, this would not be considered a finding.  If this setting does not affect the use of an external password filter, it will be enabled for fall-back purposes.
'

# START_DESCRIBE WN12-AC-000008
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-AC-000008

end
