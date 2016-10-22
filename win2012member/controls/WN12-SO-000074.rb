# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000074 - The system must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing.'

control 'WN12-SO-000074' do
  impact 0.5
  title 'The system must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing.'
  desc '
This setting ensures that the system uses algorithms that are FIPS-compliant for encryption, hashing, and signing.  FIPS-compliant algorithms meet specific standards established by the U.S. Government and must be the algorithms used for all OS encryption functions.
'
  tag 'stig','WN12-SO-000074'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000074_chk'
  tag fixid: 'F-WN12-SO-000074_fix'
  tag version: 'WN12-SO-000074'
  tag ruleid: 'WN12-SO-000074_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\

Value Name: Enabled

Value Type: REG_DWORD
Value: 1
 
Warning: Clients with this setting enabled will not be able to communicate via digitally encrypted or signed protocols with servers that do not support these algorithms.  Both the browser and web server must be configured to use TLS, or the browser will not be able to connect to a secure site.
'

# START_DESCRIBE WN12-SO-000074
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000074

end
