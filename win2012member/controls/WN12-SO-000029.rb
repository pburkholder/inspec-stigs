# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000029 - The Windows SMB client must be enabled to perform SMB packet signing when possible.'

control 'WN12-SO-000029' do
  impact 0.5
  title 'The Windows SMB client must be enabled to perform SMB packet signing when possible.'
  desc '
The server message block (SMB) protocol provides the basis for many network operations.   If this policy is enabled, the SMB client will request packet signing when communicating with an SMB server that is enabled or required to perform SMB packet signing.
'
  tag 'stig','WN12-SO-000029'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000029_chk'
  tag fixid: 'F-WN12-SO-000029_fix'
  tag version: 'WN12-SO-000029'
  tag ruleid: 'WN12-SO-000029_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Microsoft network client: Digitally sign communications (if server agrees)" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\LanmanWorkstation\Parameters\

Value Name: EnableSecuritySignature

Value Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-SO-000029
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000029

end
