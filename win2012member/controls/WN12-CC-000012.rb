# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000012 - The configuration of wireless devices using Windows Connect Now must be disabled.'

control 'WN12-CC-000012' do
  impact 0.5
  title 'The configuration of wireless devices using Windows Connect Now must be disabled.'
  desc '
Windows Connect Now allows the discovery and configuration of devices over wireless.  Wireless devices must be managed.  If a rogue device is connected to a system, there is potential for sensitive information to be compromised.
'
  tag 'stig','WN12-CC-000012'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000012_chk'
  tag fixid: 'F-WN12-CC-000012_fix'
  tag version: 'WN12-CC-000012'
  tag ruleid: 'WN12-CC-000012_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Windows Connect Now -> "Configuration of wireless settings using Windows Connect Now" to "Disabled".
'
  tag checktext: '
If the following registry values do not exist or are not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\WCN\Registrars\

Value Name: DisableFlashConfigRegistrar
Value Name: DisableInBand802DOT11Registrar
Value Name: DisableUPnPRegistrar
Value Name: DisableWPDRegistrar
Value Name: EnableRegistrars

Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-CC-000012
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000012

end
