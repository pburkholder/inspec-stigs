# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000089 - The print driver installation privilege must be restricted to administrators.'

control 'WN12-SO-000089' do
  impact 0.1
  title 'The print driver installation privilege must be restricted to administrators.'
  desc '
Allowing users to install drivers can introduce malware or cause the instability of a system.  This capability should be restricted to administrators.
'
  tag 'stig','WN12-SO-000089'
  tag severity: 'low'
  tag checkid: 'C-WN12-SO-000089_chk'
  tag fixid: 'F-WN12-SO-000089_fix'
  tag version: 'WN12-SO-000089'
  tag ruleid: 'WN12-SO-000089_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Devices: Prevent users from installing printer drivers" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers

Value Name: AddPrinterDrivers

Value Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-SO-000089
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000089

end
