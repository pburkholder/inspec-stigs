# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000064 - Kerberos encryption types must be configured to prevent the use of DES encryption suites.'

control 'WN12-SO-000064' do
  impact 0.5
  title 'Kerberos encryption types must be configured to prevent the use of DES encryption suites.'
  desc '
Certain encryption types are no longer considered secure.  This setting configures a minimum encryption type for Kerberos, preventing the use of the DES encryption suites.
'
  tag 'stig','WN12-SO-000064'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000064_chk'
  tag fixid: 'F-WN12-SO-000064_fix'
  tag version: 'WN12-SO-000064'
  tag ruleid: 'WN12-SO-000064_rule'
  tag fixtext: '
The default configuration supports this requirement.  If Kerberos encryption types must be configured, ensure that the following are not selected:

DES_CBC_CRC
DES_CBC_MD5

If the policy for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: Configure encryption types allowed for Kerberos" is configured, only the following selections are allowed:

RC4_HMAC_MD5
AES128_HMAC_SHA1
AES256_HMAC_SHA1
Future encryption types
'
  tag checktext: '
Verify that DES encryption types are not allowed for Kerberos.

If the following registry value does not exist, this is not a finding:

If the registry value does exist and is configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \Sofware\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\

Value Name: SupportedEncryptionTypes

Type: REG_DWORD
Value: 1, 2, or 3 are a finding.
'

# START_DESCRIBE WN12-SO-000064
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000064

end
