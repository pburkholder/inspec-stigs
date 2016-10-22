# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-AC-000007 - Passwords must, at a minimum, be 14 characters.'

control 'WN12-AC-000007' do
  impact 0.5
  title 'Passwords must, at a minimum, be 14 characters.'
  desc '
Information systems not protected with strong password schemes (including passwords of minimum length) provide the opportunity for anyone to crack the password, thus gaining access to the system and compromising the device, information, or the local network.
'
  tag 'stig','WN12-AC-000007'
  tag severity: 'medium'
  tag checkid: 'C-WN12-AC-000007_chk'
  tag fixid: 'F-WN12-AC-000007_fix'
  tag version: 'WN12-AC-000007'
  tag ruleid: 'WN12-AC-000007_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy -> "Minimum password length" to "14" characters.
'
  tag checktext: '
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy.

If the value for the "Minimum password length," is less than "14" characters, this is a finding.
'

# START_DESCRIBE WN12-AC-000007
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-AC-000007

end
