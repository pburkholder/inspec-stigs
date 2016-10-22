# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000128 - The Windows Remote Management (WinRM) service must not store RunAs credentials.'

control 'WN12-CC-000128' do
  impact 0.5
  title 'The Windows Remote Management (WinRM) service must not store RunAs credentials.'
  desc '
Storage of administrative credentials could allow unauthorized access.  Disallowing the storage of RunAs credentials for Windows Remote Management will prevent them from being used with plug-ins.
'
  tag 'stig','WN12-CC-000128'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000128_chk'
  tag fixid: 'F-WN12-CC-000128_fix'
  tag version: 'WN12-CC-000128'
  tag ruleid: 'WN12-CC-000128_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Service -> "Disallow WinRM from storing RunAs credentials" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\WinRM\Service\

Value Name: DisableRunAs

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000128
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000128

end
