# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000027 - Early Launch Antimalware, Boot-Start Driver Initialization Policy must be enabled and configured to only Good and Unknown.'

control 'WN12-CC-000027' do
  impact 0.5
  title 'Early Launch Antimalware, Boot-Start Driver Initialization Policy must be enabled and configured to only Good and Unknown.'
  desc '
Compromised boot drivers can introduce malware prior to some protection mechanisms that load after initialization.  The Early Launch Antimalware driver can limit allowed drivers based on classifications determined by the malware protection application.  At a minimum, drivers determined to be bad must not be allowed.
'
  tag 'stig','WN12-CC-000027'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000027_chk'
  tag fixid: 'F-WN12-CC-000027_fix'
  tag version: 'WN12-CC-000027'
  tag ruleid: 'WN12-CC-000027_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Early Launch Antimalware -> "Boot-Start Driver Initialization Policy" to "Enabled" with "Good and Unknown" selected.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \System\CurrentControlSet\Policies\EarlyLaunch\

Value Name: DriverLoadPolicy

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000027
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000027

end
