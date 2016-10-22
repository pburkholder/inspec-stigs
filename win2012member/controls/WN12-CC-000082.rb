# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000082 - The Enhanced Mitigation Experience Toolkit (EMET) system-wide Data Execution Prevention (DEP) must be enabled and configured to at least Application Opt Out.'

control 'WN12-CC-000082' do
  impact 0.5
  title 'The Enhanced Mitigation Experience Toolkit (EMET) system-wide Data Execution Prevention (DEP) must be enabled and configured to at least Application Opt Out.'
  desc '
Attackers are constantly looking for vulnerabilities in systems and applications.  The Enhanced Mitigation Experience Toolkit can enable several mechanisms, such as Data Execution Prevention (DEP), Address Space Layout Randomization (ASLR), and Structured Exception Handler Overwrite Protection (SEHOP) on the system and applications, adding additional levels of protection.
'
  tag 'stig','WN12-CC-000082'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000082_chk'
  tag fixid: 'F-WN12-CC-000082_fix'
  tag version: 'WN12-CC-000082'
  tag ruleid: 'WN12-CC-000082_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> EMET -> "System DEP" to "Enabled" with at least "Application Opt Out" selected. 

The Enhanced Mitigation Experience Toolkit must be installed on the system and the administrative template files added to make this setting available.

Document applications that do not function properly due to this setting, and are opted out, with the IAO.

Opted out exceptions can be configured with the following command:
EMET_Conf --Set "application path\executable name" -DEP

Alternately, configure exceptions in System Properties:
Select "System" in Control Panel.
Select "Advanced system settings".
Click "Settings" in the "Performance" section.
Select the "Data Execution Prevention" tab.
Select "Turn on DEP for all programs and services except those I select:".

Applications that are opted out are configured in the window below this selection.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \Software\Policies\Microsoft\EMET\SysSettings\

Value Name: DEP

Type: REG_DWORD
Value: 2 (Application Opt Out)

Applications that do not function properly due to this setting, and are opted out, must be documented with the IAO.
'

# START_DESCRIBE WN12-CC-000082
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000082

end
