# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-AC-000006 - The minimum password age must meet requirements.'

control 'WN12-AC-000006' do
  impact 0.5
  title 'The minimum password age must meet requirements.'
  desc '
Permitting passwords to be changed in immediate succession within the same day allows users to cycle passwords through their history database.  This enables users to effectively negate the purpose of mandating periodic password changes.
'
  tag 'stig','WN12-AC-000006'
  tag severity: 'medium'
  tag checkid: 'C-WN12-AC-000006_chk'
  tag fixid: 'F-WN12-AC-000006_fix'
  tag version: 'WN12-AC-000006'
  tag ruleid: 'WN12-AC-000006_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy -> "Minimum Password Age" to at least "1" day.
'
  tag checktext: '
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy.

If the value for the "Minimum password age" is set to "0" days ("Password can be changed immediately."), this is a finding.
'

# START_DESCRIBE WN12-AC-000006
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-AC-000006

end
