# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-AC-000009 - Reversible password encryption must be disabled.'

control 'WN12-AC-000009' do
  impact 1.0
  title 'Reversible password encryption must be disabled.'
  desc '
Storing passwords using reversible encryption is essentially the same as storing clear-text versions of the passwords.  For this reason, this policy must never be enabled.
'
  tag 'stig','WN12-AC-000009'
  tag severity: 'high'
  tag checkid: 'C-WN12-AC-000009_chk'
  tag fixid: 'F-WN12-AC-000009_fix'
  tag version: 'WN12-AC-000009'
  tag ruleid: 'WN12-AC-000009_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy -> "Store password using reversible encryption" to "Disabled".
'
  tag checktext: '
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy.

If the value for "Store password using reversible encryption" is not set to "Disabled", this is a finding.
'

# START_DESCRIBE WN12-AC-000009
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-AC-000009

end
