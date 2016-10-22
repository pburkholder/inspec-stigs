# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000075 - The use of biometrics must be disabled.'

control 'WN12-CC-000075' do
  impact 0.5
  title 'The use of biometrics must be disabled.'
  desc '
Allowing biometrics may bypass required authentication methods.  Biometrics may only be used as an additional authentication factor where an enhanced strength of identity credential is necessary or desirable.  Additional factors must be met per DoD policy.
'
  tag 'stig','WN12-CC-000075'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000075_chk'
  tag fixid: 'F-WN12-CC-000075_fix'
  tag version: 'WN12-CC-000075'
  tag ruleid: 'WN12-CC-000075_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Biometrics -> "Allow the use of biometrics" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Biometrics\

Value Name: Enabled

Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-CC-000075
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000075

end
