# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000035 - The service principal name (SPN) target name validation level must be turned off.'

control 'WN12-SO-000035' do
  impact 0.5
  title 'The service principal name (SPN) target name validation level must be turned off.'
  desc '
If a service principle name (SPN) is provided by the client, it is validated against the server\'s list of SPNs.  Implementation may disrupt file and print sharing capabilities.
'
  tag 'stig','WN12-SO-000035'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000035_chk'
  tag fixid: 'F-WN12-SO-000035_fix'
  tag version: 'WN12-SO-000035'
  tag ruleid: 'WN12-SO-000035_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Microsoft network server: Server SPN target name validation level" to "Off".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \System\CurrentControlSet\Services\LanmanServer\Parameters\

Value Name: SmbServerNameHardeningLevel

Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-SO-000035
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000035

end
