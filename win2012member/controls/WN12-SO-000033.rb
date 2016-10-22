# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000033 - The Windows SMB server must perform SMB packet signing when possible.'

control 'WN12-SO-000033' do
  impact 0.5
  title 'The Windows SMB server must perform SMB packet signing when possible.'
  desc '
The server message block (SMB) protocol provides the basis for many network operations.   Digitally signed SMB packets aid in preventing man-in-the-middle attacks.  If this policy is enabled, the SMB server will negotiate SMB packet signing as requested by the client.
'
  tag 'stig','WN12-SO-000033'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000033_chk'
  tag fixid: 'F-WN12-SO-000033_fix'
  tag version: 'WN12-SO-000033'
  tag ruleid: 'WN12-SO-000033_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Microsoft network server: Digitally sign communications (if client agrees)" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\LanManServer\Parameters\

Value Name: EnableSecuritySignature

Value Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-SO-000033
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000033

end
